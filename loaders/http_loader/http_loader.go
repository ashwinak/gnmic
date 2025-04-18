package http_loader

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/karimra/gnmic/actions"
	"github.com/karimra/gnmic/loaders"
	"github.com/karimra/gnmic/types"
	"github.com/karimra/gnmic/utils"
	"gopkg.in/yaml.v2"
)

const (
	loggingPrefix   = "[http_loader] "
	loaderType      = "http"
	defaultInterval = 1 * time.Minute
	defaultTimeout  = 50 * time.Second
)

func init() {
	loaders.Register(loaderType, func() loaders.TargetLoader {
		return &httpLoader{
			cfg:         &cfg{},
			lastTargets: make(map[string]*types.TargetConfig),
			logger:      log.New(io.Discard, loggingPrefix, utils.DefaultLoggingFlags),
		}
	})
}

type httpLoader struct {
	cfg            *cfg
	m              *sync.RWMutex
	lastTargets    map[string]*types.TargetConfig
	targetConfigFn func(*types.TargetConfig) error
	logger         *log.Logger
	//
	vars          map[string]interface{}
	actionsConfig map[string]map[string]interface{}
	addActions    []actions.Action
	delActions    []actions.Action
	numActions    int
}

type cfg struct {
	// the server URL, must include http or https as a prefix
	URL string `json:"url,omitempty" mapstructure:"url,omitempty"`
	// server query interval
	Interval time.Duration `json:"interval,omitempty" mapstructure:"interval,omitempty"`
	// query timeout
	Timeout time.Duration `json:"timeout,omitempty" mapstructure:"timeout,omitempty"`
	// TLS config
	SkipVerify bool   `json:"skip-verify,omitempty" mapstructure:"skip-verify,omitempty"`
	CAFile     string `json:"ca-file,omitempty" mapstructure:"ca-file,omitempty"`
	CertFile   string `json:"cert-file,omitempty" mapstructure:"cert-file,omitempty"`
	KeyFile    string `json:"key-file,omitempty" mapstructure:"key-file,omitempty"`
	// HTTP basicAuth
	Username string `json:"username,omitempty" mapstructure:"username,omitempty"`
	Password string `json:"password,omitempty" mapstructure:"password,omitempty"`
	// Oauth2
	Token string `json:"token,omitempty" mapstructure:"token,omitempty"`
	// if true, registers httpLoader prometheus metrics with the provided
	// prometheus registry
	EnableMetrics bool `json:"enable-metrics,omitempty" mapstructure:"enable-metrics,omitempty"`
	// enable Debug
	Debug bool `json:"debug,omitempty" mapstructure:"debug,omitempty"`
	// variables definitions to be passed to the actions
	Vars map[string]interface{}
	// variable file, values in this file will be overwritten by
	// the ones defined in Vars
	VarsFile string `mapstructure:"vars-file,omitempty"`
	// list of Actions to run on new target discovery
	OnAdd []string `json:"on-add,omitempty" mapstructure:"on-add,omitempty"`
	// list of Actions to run on target removal
	OnDelete []string `json:"on-delete,omitempty" mapstructure:"on-delete,omitempty"`
}

func (h *httpLoader) Init(ctx context.Context, cfg map[string]interface{}, logger *log.Logger, opts ...loaders.Option) error {
	err := loaders.DecodeConfig(cfg, h.cfg)
	if err != nil {
		return err
	}
	err = h.setDefaults()
	if err != nil {
		return err
	}
	for _, o := range opts {
		o(h)
	}
	if logger != nil {
		h.logger.SetOutput(logger.Writer())
		h.logger.SetFlags(logger.Flags())
	}
	err = h.readVars()
	if err != nil {
		return err
	}
	for _, actName := range h.cfg.OnAdd {
		if cfg, ok := h.actionsConfig[actName]; ok {
			a, err := h.initializeAction(cfg)
			if err != nil {
				return err
			}
			h.addActions = append(h.addActions, a)
			continue
		}
		return fmt.Errorf("unknown action name %q", actName)

	}
	for _, actName := range h.cfg.OnDelete {
		if cfg, ok := h.actionsConfig[actName]; ok {
			a, err := h.initializeAction(cfg)
			if err != nil {
				return err
			}
			h.delActions = append(h.delActions, a)
			continue
		}
		return fmt.Errorf("unknown action name %q", actName)
	}
	h.numActions = len(h.addActions) + len(h.delActions)
	return nil
}

func (h *httpLoader) Start(ctx context.Context) chan *loaders.TargetOperation {
	opChan := make(chan *loaders.TargetOperation)
	ticker := time.NewTicker(h.cfg.Interval)
	go func() {
		defer close(opChan)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				readTargets, err := h.getTargets()
				if err != nil {
					h.logger.Printf("failed to read targets from HTTP server: %v", err)
					continue
				}
				select {
				case <-ctx.Done():
					return
				default:
					h.updateTargets(ctx, readTargets, opChan)
				}
			}
		}
	}()
	return opChan
}

func (h *httpLoader) setDefaults() error {
	if h.cfg.URL == "" {
		return errors.New("missing URL")
	}
	if h.cfg.Interval <= 0 {
		h.cfg.Interval = defaultInterval
	}
	if h.cfg.Timeout <= 0 {
		h.cfg.Timeout = defaultTimeout
	}
	return nil
}

func (h *httpLoader) getTargets() (map[string]*types.TargetConfig, error) {
	c := resty.New()
	tlsCfg, err := utils.NewTLSConfig(h.cfg.CAFile, h.cfg.CertFile, h.cfg.KeyFile, h.cfg.SkipVerify, false)
	if err != nil {
		httpLoaderFailedGetRequests.WithLabelValues(loaderType, fmt.Sprintf("%v", err))
		return nil, err
	}
	if tlsCfg != nil {
		c = c.SetTLSClientConfig(tlsCfg)
	}
	c.SetTimeout(h.cfg.Timeout)
	if h.cfg.Username != "" && h.cfg.Password != "" {
		c.SetBasicAuth(h.cfg.Username, h.cfg.Password)
	}
	if h.cfg.Token != "" {
		c.SetAuthToken(h.cfg.Token)
	}
	result := make(map[string]*types.TargetConfig)
	start := time.Now()
	httpLoaderGetRequestsTotal.WithLabelValues(loaderType).Add(1)
	rsp, err := c.R().SetResult(result).Get(h.cfg.URL)
	if err != nil {
		return nil, err
	}
	httpLoaderGetRequestDuration.WithLabelValues(loaderType).Set(float64(time.Since(start).Nanoseconds()))
	if rsp.StatusCode() != 200 {
		httpLoaderFailedGetRequests.WithLabelValues(loaderType, rsp.Status())
		return nil, fmt.Errorf("failed request, code=%d", rsp.StatusCode())
	}
	return rsp.Result().(map[string]*types.TargetConfig), nil
}

func (h *httpLoader) updateTargets(ctx context.Context, tcs map[string]*types.TargetConfig, opChan chan *loaders.TargetOperation) {
	var err error
	for _, tc := range tcs {
		err = h.targetConfigFn(tc)
		if err != nil {
			h.logger.Printf("failed running target config fn on target %q", tc.Name)
		}
	}
	targetOp, err := h.runActions(ctx, tcs, loaders.Diff(h.lastTargets, tcs))
	if err != nil {
		h.logger.Printf("failed to run actions: %v", err)
		return
	}
	numAdds := len(targetOp.Add)
	numDels := len(targetOp.Del)
	defer func() {
		httpLoaderLoadedTargets.WithLabelValues(loaderType).Set(float64(numAdds))
		httpLoaderDeletedTargets.WithLabelValues(loaderType).Set(float64(numDels))
	}()
	if numAdds+numDels == 0 {
		return
	}
	h.m.Lock()
	for _, t := range targetOp.Add {
		if _, ok := h.lastTargets[t.Name]; !ok {
			h.lastTargets[t.Name] = t
		}
	}
	for _, n := range targetOp.Del {
		delete(h.lastTargets, n)
	}
	h.m.Unlock()
	opChan <- targetOp
}

func (h *httpLoader) readVars() error {
	if h.cfg.VarsFile == "" {
		h.vars = h.cfg.Vars
		return nil
	}
	b, err := utils.ReadFile(context.TODO(), h.cfg.VarsFile)
	if err != nil {
		return err
	}
	v := make(map[string]interface{})
	err = yaml.Unmarshal(b, &v)
	if err != nil {
		return err
	}
	h.vars = utils.MergeMaps(v, h.cfg.Vars)
	return nil
}

func (h *httpLoader) initializeAction(cfg map[string]interface{}) (actions.Action, error) {
	if len(cfg) == 0 {
		return nil, errors.New("missing action definition")
	}
	if actType, ok := cfg["type"]; ok {
		switch actType := actType.(type) {
		case string:
			if in, ok := actions.Actions[actType]; ok {
				act := in()
				err := act.Init(cfg, actions.WithLogger(h.logger), actions.WithTargets(nil))
				if err != nil {
					return nil, err
				}

				return act, nil
			}
			return nil, fmt.Errorf("unknown action type %q", actType)
		default:
			return nil, fmt.Errorf("unexpected action field type %T", actType)
		}
	}
	return nil, errors.New("missing type field under action")
}

func (f *httpLoader) runActions(ctx context.Context, tcs map[string]*types.TargetConfig, targetOp *loaders.TargetOperation) (*loaders.TargetOperation, error) {
	if f.numActions == 0 {
		return targetOp, nil
	}
	opChan := make(chan *loaders.TargetOperation)
	// some actions are defined,
	doneCh := make(chan struct{})
	result := &loaders.TargetOperation{
		Add: make([]*types.TargetConfig, 0, len(targetOp.Add)),
		Del: make([]string, 0, len(targetOp.Del)),
	}
	// start operation gathering goroutine
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case op, ok := <-opChan:
				if !ok {
					close(doneCh)
					return
				}
				result.Add = append(result.Add, op.Add...)
				result.Del = append(result.Del, op.Del...)
			}
		}
	}()
	// create waitGroup and add the number of target operations to it
	wg := new(sync.WaitGroup)
	wg.Add(len(targetOp.Add) + len(targetOp.Del))
	// run OnAdd actions
	for _, tAdd := range targetOp.Add {
		go func(tc *types.TargetConfig) {
			defer wg.Done()
			err := f.runOnAddActions(tc.Name, tcs)
			if err != nil {
				f.logger.Printf("failed running OnAdd actions: %v", err)
				return
			}
			opChan <- &loaders.TargetOperation{Add: []*types.TargetConfig{tc}}
		}(tAdd)
	}
	// run OnDelete actions
	for _, tDel := range targetOp.Del {
		go func(name string) {
			defer wg.Done()
			err := f.runOnDeleteActions(name, tcs)
			if err != nil {
				f.logger.Printf("failed running OnDelete actions: %v", err)
				return
			}
			opChan <- &loaders.TargetOperation{Del: []string{name}}
		}(tDel)
	}
	wg.Wait()
	close(opChan)
	<-doneCh //wait for gathering goroutine to finish
	return result, nil
}

func (d *httpLoader) runOnAddActions(tName string, tcs map[string]*types.TargetConfig) error {
	aCtx := &actions.Context{
		Input:   tName,
		Env:     make(map[string]interface{}),
		Vars:    d.vars,
		Targets: tcs,
	}
	for _, act := range d.addActions {
		d.logger.Printf("running action %q for target %q", act.NName(), tName)
		res, err := act.Run(aCtx)
		if err != nil {
			// delete target from known targets map
			d.m.Lock()
			delete(d.lastTargets, tName)
			d.m.Unlock()
			return fmt.Errorf("action %q for target %q failed: %v", act.NName(), tName, err)
		}

		aCtx.Env[act.NName()] = utils.Convert(res)
		if d.cfg.Debug {
			d.logger.Printf("action %q, target %q result: %+v", act.NName(), tName, res)
			b, _ := json.MarshalIndent(aCtx, "", "  ")
			d.logger.Printf("action %q context:\n%s", act.NName(), string(b))
		}
	}
	return nil
}

func (d *httpLoader) runOnDeleteActions(tName string, tcs map[string]*types.TargetConfig) error {
	env := make(map[string]interface{})
	for _, act := range d.delActions {
		res, err := act.Run(&actions.Context{Input: tName, Env: env, Vars: d.vars})
		if err != nil {
			return fmt.Errorf("action %q for target %q failed: %v", act.NName(), tName, err)
		}
		env[act.NName()] = res
	}
	return nil
}
