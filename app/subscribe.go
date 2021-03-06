package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/karimra/gnmic/collector"
	"github.com/karimra/gnmic/config"
	"github.com/karimra/gnmic/formatters"
	"github.com/manifoldco/promptui"
	"github.com/openconfig/gnmi/proto/gnmi"
	"github.com/spf13/cobra"
)

const (
	initLockerRetryTimer = 1 * time.Second
)

func (a *App) SubscribeRun(cmd *cobra.Command, args []string) error {
	if a.PromptMode {
		return a.SubscribeRunPrompt(cmd, args)
	}
	err := a.Config.GetClustering()
	if err != nil {
		return err
	}
	//
	for {
		err := a.InitLocker()
		if err != nil {
			a.Logger.Printf("failed to init locker: %v", err)
			time.Sleep(initLockerRetryTimer)
			continue
		}
		break
	}
	targetsConfig, err := a.Config.GetTargets()
	if (errors.Is(err, config.ErrNoTargetsFound) && !a.Config.LocalFlags.SubscribeWatchConfig) ||
		(!errors.Is(err, config.ErrNoTargetsFound) && err != nil) {
		return fmt.Errorf("failed reading targets config: %v", err)
	}

	cOpts, err := a.createCollectorOpts(cmd)
	if err != nil {
		return err
	}
	//
	a.collector = collector.NewCollector(a.collectorConfig(), targetsConfig, cOpts...)

	a.startAPI()
	go a.startCluster()
	a.startIO()

	a.handlePolledSubscriptions()
	if a.Config.LocalFlags.SubscribeWatchConfig {
		go a.watchConfig()
	}

	for range a.ctx.Done() {
		return a.ctx.Err()
	}
	return nil
}

func (a *App) Subscribe(ctx context.Context, name string) {
	defer a.wg.Done()
	a.collector.StartTarget(ctx, name)
}

func (a *App) SubscribeRunPrompt(cmd *cobra.Command, args []string) error {
	targetsConfig, err := a.Config.GetTargets()
	if err != nil {
		return fmt.Errorf("failed reading targets config: %v", err)
	}

	subscriptionsConfig, err := a.Config.GetSubscriptions(cmd)
	if err != nil {
		return fmt.Errorf("failed reading subscriptions config: %v", err)
	}
	outs, err := a.Config.GetOutputs()
	if err != nil {
		return fmt.Errorf("failed reading outputs config: %v", err)
	}
	cOpts, err := a.createCollectorOpts(cmd)
	if err != nil {
		return err
	}
	//
	if a.collector == nil {
		a.collector = collector.NewCollector(a.collectorConfig(), targetsConfig, cOpts...)
		go a.collector.Start(a.ctx)
		a.startAPI()
		go a.startCluster()
	} else {
		// prompt mode
		for name, outCfg := range outs {
			err = a.collector.AddOutput(name, outCfg)
			if err != nil {
				a.Logger.Printf("%v", err)
			}
		}
		for _, sc := range subscriptionsConfig {
			err = a.collector.AddSubscriptionConfig(sc)
			if err != nil {
				a.Logger.Printf("%v", err)
			}
		}
		for _, tc := range targetsConfig {
			a.collector.AddTarget(tc)
			if err != nil {
				a.Logger.Printf("%v", err)
			}
		}
	}

	a.collector.InitOutputs(a.ctx)
	a.collector.InitInputs(a.ctx)
	a.collector.InitTargets()

	var limiter *time.Ticker
	if a.Config.LocalFlags.SubscribeBackoff > 0 {
		limiter = time.NewTicker(a.Config.LocalFlags.SubscribeBackoff)
	}

	a.wg.Add(len(a.collector.Targets))
	for name := range a.collector.Targets {
		go a.Subscribe(a.ctx, name)
		if limiter != nil {
			<-limiter.C
		}
	}
	if limiter != nil {
		limiter.Stop()
	}
	a.wg.Wait()

	a.handlePolledSubscriptions()
	return nil
}

func (a *App) createCollectorOpts(cmd *cobra.Command) ([]collector.CollectorOption, error) {
	inputsConfig, err := a.Config.GetInputs()
	if err != nil {
		return nil, fmt.Errorf("failed reading inputs config: %v", err)
	}
	subscriptionsConfig, err := a.Config.GetSubscriptions(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed reading subscriptions config: %v", err)
	}
	outs, err := a.Config.GetOutputs()
	if err != nil {
		return nil, fmt.Errorf("failed reading outputs config: %v", err)
	}
	epConfig, err := a.Config.GetEventProcessors()
	if err != nil {
		return nil, fmt.Errorf("failed reading event processors config: %v", err)
	}

	return []collector.CollectorOption{
		collector.WithDialOptions(a.createCollectorDialOpts()),
		collector.WithSubscriptions(subscriptionsConfig),
		collector.WithOutputs(outs),
		collector.WithLogger(a.Logger),
		collector.WithEventProcessors(epConfig),
		collector.WithInputs(inputsConfig),
		collector.WithLocker(a.locker),
	}, nil
}

func (a *App) collectorConfig() *collector.Config {
	cfg := &collector.Config{
		PrometheusAddress:   a.Config.PrometheusAddress,
		Debug:               a.Config.Debug,
		Format:              a.Config.Format,
		TargetReceiveBuffer: a.Config.TargetBufferSize,
		RetryTimer:          a.Config.Retry,
		LockRetryTimer:      a.Config.LocalFlags.SubscribeLockRetry,
	}
	if a.Config.Clustering != nil {
		cfg.ClusterName = a.Config.Clustering.ClusterName
		cfg.Name = a.Config.Clustering.InstanceName
	}
	if cfg.ClusterName == "" {
		cfg.ClusterName = a.Config.SubscribeClusterName
	}
	if cfg.Name == "" {
		cfg.Name = a.Config.GlobalFlags.InstanceName
	}
	a.Logger.Printf("starting collector with config %+v", cfg)
	return cfg
}

func (a *App) handlePolledSubscriptions() {
	polledTargetsSubscriptions := a.collector.PolledSubscriptionsTargets()
	if len(polledTargetsSubscriptions) > 0 {
		pollTargets := make([]string, 0, len(polledTargetsSubscriptions))
		for t := range polledTargetsSubscriptions {
			pollTargets = append(pollTargets, t)
		}
		sort.Slice(pollTargets, func(i, j int) bool {
			return pollTargets[i] < pollTargets[j]
		})
		s := promptui.Select{
			Label:        "select target to poll",
			Items:        pollTargets,
			HideSelected: true,
		}
		waitChan := make(chan struct{}, 1)
		waitChan <- struct{}{}
		mo := &formatters.MarshalOptions{
			Multiline: true,
			Indent:    "  ",
			Format:    a.Config.Format,
		}
		go func() {
			for {
				select {
				case <-waitChan:
					_, name, err := s.Run()
					if err != nil {
						fmt.Printf("failed selecting target to poll: %v\n", err)
						continue
					}
					ss := promptui.Select{
						Label:        "select subscription to poll",
						Items:        polledTargetsSubscriptions[name],
						HideSelected: true,
					}
					_, subName, err := ss.Run()
					if err != nil {
						fmt.Printf("failed selecting subscription to poll: %v\n", err)
						continue
					}
					response, err := a.collector.TargetPoll(name, subName)
					if err != nil && err != io.EOF {
						fmt.Printf("target '%s', subscription '%s': poll response error:%v\n", name, subName, err)
						continue
					}
					if response == nil {
						fmt.Printf("received empty response from target '%s'\n", name)
						continue
					}
					switch rsp := response.Response.(type) {
					case *gnmi.SubscribeResponse_SyncResponse:
						fmt.Printf("received sync response '%t' from '%s'\n", rsp.SyncResponse, name)
						waitChan <- struct{}{}
						continue
					}
					b, err := mo.Marshal(response, nil)
					if err != nil {
						fmt.Printf("target '%s', subscription '%s': poll response formatting error:%v\n", name, subName, err)
						fmt.Println(string(b))
						waitChan <- struct{}{}
						continue
					}
					fmt.Println(string(b))
					waitChan <- struct{}{}
				case <-a.ctx.Done():
					return
				}
			}
		}()
	}
}

func (a *App) startIO() {
	go a.collector.Start(a.ctx)
	a.collector.InitOutputs(a.ctx)
	a.collector.InitInputs(a.ctx)
	a.collector.InitTargets()
	if !a.inCluster() {
		var limiter *time.Ticker
		if a.Config.LocalFlags.SubscribeBackoff > 0 {
			limiter = time.NewTicker(a.Config.LocalFlags.SubscribeBackoff)
		}

		a.wg.Add(len(a.collector.Targets))
		for name := range a.collector.Targets {
			go a.Subscribe(a.ctx, name)
			if limiter != nil {
				<-limiter.C
			}
		}
		if limiter != nil {
			limiter.Stop()
		}
		a.wg.Wait()
	}
}
