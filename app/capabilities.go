package app

import (
	"context"
	"fmt"

	"github.com/karimra/gnmic/collector"
	"github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/gnmi/proto/gnmi_ext"
	"github.com/spf13/cobra"
)

func (a *App) CapRun(cmd *cobra.Command, args []string) error {
	if a.Config.Format == "event" {
		return fmt.Errorf("format event not supported for Capabilities RPC")
	}
	ctx, cancel := context.WithCancel(a.ctx)
	defer cancel()
	targetsConfig, err := a.Config.GetTargets()
	if err != nil {
		a.Logger.Printf("failed getting targets config: %v", err)
		return fmt.Errorf("failed getting targets config: %v", err)
	}
	if a.collector == nil {
		cfg := &collector.Config{
			Debug:               a.Config.Debug,
			Format:              a.Config.Format,
			TargetReceiveBuffer: a.Config.TargetBufferSize,
			RetryTimer:          a.Config.Retry,
		}

		a.collector = collector.NewCollector(cfg, targetsConfig,
			collector.WithDialOptions(a.createCollectorDialOpts()),
			collector.WithLogger(a.Logger),
		)
	} else {
		// prompt mode
		for _, tc := range targetsConfig {
			a.collector.AddTarget(tc)
		}
	}
	a.collector.InitTargets()
	a.wg.Add(len(a.collector.Targets))
	for tName := range a.collector.Targets {
		go a.ReqCapabilities(ctx, tName)
	}
	a.wg.Wait()
	return nil
}

func (a *App) ReqCapabilities(ctx context.Context, tName string) {
	defer a.wg.Done()
	ext := make([]*gnmi_ext.Extension, 0) //
	if a.Config.PrintRequest {
		err := a.Print(tName, "Capabilities Request:", &gnmi.CapabilityRequest{
			Extension: ext,
		})
		if err != nil {
			a.Logger.Printf("%v", err)
			if !a.Config.Log {
				fmt.Printf("target %s: %v\n", tName, err)
			}
		}
	}

	a.Logger.Printf("sending gNMI CapabilityRequest: gnmi_ext.Extension='%v' to %s", ext, tName)
	response, err := a.collector.Capabilities(ctx, tName, ext...)
	if err != nil {
		a.Logger.Printf("error sending capabilities request: %v", err)
		return
	}

	err = a.Print(tName, "Capabilities Response:", response)
	if err != nil {
		a.Logger.Printf("target %s: %v", tName, err)
	}
}
