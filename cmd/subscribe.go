// Copyright © 2020 Karim Radhouani <medkarimrdi@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/gnxi/utils/xpath"
	"github.com/openconfig/gnmi/proto/gnmi"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc/metadata"
)

type msg struct {
	Meta             map[string]interface{} `json:"meta,omitempty"`
	Source           string                 `json:"source,omitempty"`
	SystemName       string                 `json:"system-name,omitempty"`
	SubscriptionName string                 `json:"subscription-name,omitempty"`
	Timestamp        int64                  `json:"timestamp,omitempty"`
	Time             *time.Time             `json:"time,omitempty"`
	Prefix           string                 `json:"prefix,omitempty"`
	Updates          []*update              `json:"updates,omitempty"`
	Deletes          []string               `json:"deletes,omitempty"`
}
type update struct {
	Path   string
	Values map[string]interface{} `json:"values,omitempty"`
}

// subscribeCmd represents the subscribe command
var subscribeCmd = &cobra.Command{
	Use:     "subscribe",
	Aliases: []string{"sub"},
	Short:   "subscribe to gnmi updates on targets",

	RunE: func(cmd *cobra.Command, args []string) error {
		var err error
		addresses := viper.GetStringSlice("address")
		if len(addresses) == 0 {
			fmt.Println("no grpc server address specified")
			return nil
		}
		username := viper.GetString("username")
		if username == "" {
			if username, err = readUsername(); err != nil {
				return err
			}
		}
		password := viper.GetString("password")
		if password == "" {
			if password, err = readPassword(); err != nil {
				return err
			}
		}
		subscReq, err := createSubscribeRequest()
		if err != nil {
			return err
		}
		polledSubsChan := make(map[string]chan struct{})
		waitChan := make(chan struct{})
		if subscReq.GetSubscribe().Mode == gnmi.SubscriptionList_POLL {
			for _, addr := range addresses {
				polledSubsChan[addr] = make(chan struct{})
			}
		}
		wg := new(sync.WaitGroup)
		wg.Add(len(addresses))
		for _, addr := range addresses {
			go func(address string) {
				defer wg.Done()
				_, _, err := net.SplitHostPort(address)
				if err != nil {
					if strings.Contains(err.Error(), "missing port in address") {
						address = net.JoinHostPort(address, defaultGrpcPort)
					} else {
						logger.Printf("error parsing address '%s': %v", address, err)
						return
					}
				}
				printPrefix := ""
				if len(addresses) > 1 && !viper.GetBool("no-prefix") {
					printPrefix = fmt.Sprintf("[%s] ", address)
				}
				conn, err := createGrpcConn(address)
				if err != nil {
					logger.Printf("connection to %s failed: %v", address, err)
					return
				}
				client := gnmi.NewGNMIClient(conn)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				ctx = metadata.AppendToOutgoingContext(ctx, "username", username, "password", password)

				subscribeClient, err := client.Subscribe(ctx)
				if err != nil {
					logger.Printf("error creating subscribe client: %v", err)
					return
				}
				err = subscribeClient.Send(subscReq)
				if err != nil {
					logger.Printf("subscribe error: %v", err)
					return
				}
				switch subscReq.GetSubscribe().Mode {
				case gnmi.SubscriptionList_ONCE, gnmi.SubscriptionList_STREAM:
					for {
						subscribeRsp, err := subscribeClient.Recv()
						if err != nil {
							logger.Printf("addr=%s rcv error: %v", address, err)
							return
						}
						switch resp := subscribeRsp.Response.(type) {
						case *gnmi.SubscribeResponse_Update:
							printSubscribeResponse(map[string]interface{}{"source": address}, subscribeRsp)
						case *gnmi.SubscribeResponse_SyncResponse:
							logger.Printf("received sync response=%+v from %s\n", resp.SyncResponse, address)
							if subscReq.GetSubscribe().Mode == gnmi.SubscriptionList_ONCE {
								return
							}
						}
						fmt.Println()
					}
				case gnmi.SubscriptionList_POLL:
					for {
						<-polledSubsChan[address]
						err = subscribeClient.Send(&gnmi.SubscribeRequest{
							Request: &gnmi.SubscribeRequest_Poll{
								Poll: &gnmi.Poll{},
							},
						})
						if err != nil {
							logger.Printf("error sending poll request:%v", err)
							waitChan <- struct{}{}
							continue
						}
						subscribeRsp, err := subscribeClient.Recv()
						if err != nil {
							logger.Printf("rcv error: %v", err)
							waitChan <- struct{}{}
							continue
						}
						switch resp := subscribeRsp.Response.(type) {
						case *gnmi.SubscribeResponse_Update:
							printSubscribeResponse(map[string]interface{}{"source": address}, subscribeRsp)
						case *gnmi.SubscribeResponse_SyncResponse:
							fmt.Printf("%ssync response: %+v\n", printPrefix, resp.SyncResponse)
						}
						waitChan <- struct{}{}
					}
				}
			}(addr)
		}
		if subscReq.GetSubscribe().Mode == gnmi.SubscriptionList_POLL {
			var address string
			for {
				fmt.Print("target to poll(ip:port): ")
				_, err := fmt.Scan(&address)
				if err != nil {
					fmt.Printf("%v\n", err)
					continue
				}
				c, ok := polledSubsChan[address]
				if !ok {
					fmt.Printf("unknown target: %s\n", address)
					continue
				}
				c <- struct{}{}
				<-waitChan
			}
		}
		wg.Wait()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(subscribeCmd)
	subscribeCmd.Flags().StringP("prefix", "", "", "subscribe request prefix")
	subscribeCmd.Flags().StringSliceP("path", "", []string{""}, "subscribe request paths")
	subscribeCmd.MarkFlagRequired("path")
	subscribeCmd.Flags().Int32P("qos", "q", 20, "qos marking")
	subscribeCmd.Flags().BoolP("updates-only", "", false, "only updates to current state should be sent")
	subscribeCmd.Flags().StringP("subscription-mode", "", "stream", "one of: once, stream, poll")
	subscribeCmd.Flags().StringP("stream-subscription-mode", "", "target-defined", "one of: on-change, sample, target-defined")
	subscribeCmd.Flags().StringP("sampling-interval", "i", "10s",
		"sampling interval as a decimal number and a suffix unit, such as \"10s\" or \"1m30s\", minimum is 1s")
	subscribeCmd.Flags().BoolP("suppress-redundant", "", false, "suppress redundant update if the subscribed value didnt not change")
	subscribeCmd.Flags().StringP("heartbeat-interval", "", "0s", "heartbeat interval in case suppress-redundant is enabled")
	subscribeCmd.Flags().StringP("model", "", "", "subscribe request used model")
	//
	viper.BindPFlag("sub-prefix", subscribeCmd.Flags().Lookup("prefix"))
	viper.BindPFlag("sub-path", subscribeCmd.Flags().Lookup("path"))
	viper.BindPFlag("qos", subscribeCmd.Flags().Lookup("qos"))
	viper.BindPFlag("updates-only", subscribeCmd.Flags().Lookup("updates-only"))
	viper.BindPFlag("subscription-mode", subscribeCmd.Flags().Lookup("subscription-mode"))
	viper.BindPFlag("stream-subscription-mode", subscribeCmd.Flags().Lookup("stream-subscription-mode"))
	viper.BindPFlag("sampling-interval", subscribeCmd.Flags().Lookup("sampling-interval"))
	viper.BindPFlag("suppress-redundant", subscribeCmd.Flags().Lookup("suppress-redundant"))
	viper.BindPFlag("heartbeat-interval", subscribeCmd.Flags().Lookup("heartbeat-interval"))
	viper.BindPFlag("sub-model", subscribeCmd.Flags().Lookup("model"))
}

func createSubscribeRequest() (*gnmi.SubscribeRequest, error) {
	paths := viper.GetStringSlice("sub-path")
	if len(paths) == 0 {
		return nil, errors.New("no path provided")
	}
	gnmiPrefix, err := xpath.ToGNMIPath(viper.GetString("sub-prefix"))
	if err != nil {
		return nil, fmt.Errorf("prefix parse error: %v", err)
	}
	encodingVal, ok := gnmi.Encoding_value[strings.Replace(strings.ToUpper(viper.GetString("encoding")), "-", "_", -1)]
	if !ok {
		return nil, fmt.Errorf("invalid encoding type '%s'", viper.GetString("encoding"))
	}
	modeVal, ok := gnmi.SubscriptionList_Mode_value[strings.ToUpper(viper.GetString("subscription-mode"))]
	if !ok {
		return nil, fmt.Errorf("invalid subscription list type '%s'", viper.GetString("subscription-mode"))
	}
	qos := &gnmi.QOSMarking{Marking: viper.GetUint32("qos")}
	samplingInterval, err := time.ParseDuration(viper.GetString("sampling-interval"))
	if err != nil {
		return nil, err
	}
	heartbeatInterval, err := time.ParseDuration(viper.GetString("heartbeat-interval"))
	if err != nil {
		return nil, err
	}
	subscriptions := make([]*gnmi.Subscription, len(paths))
	for i, p := range paths {
		gnmiPath, err := xpath.ToGNMIPath(p)
		if err != nil {
			return nil, fmt.Errorf("path parse error: %v", err)
		}
		subscriptions[i] = &gnmi.Subscription{Path: gnmiPath}
		switch gnmi.SubscriptionList_Mode(modeVal) {
		case gnmi.SubscriptionList_STREAM:
			mode, ok := gnmi.SubscriptionMode_value[strings.Replace(strings.ToUpper(viper.GetString("stream-subscription-mode")), "-", "_", -1)]
			if !ok {
				return nil, fmt.Errorf("invalid streamed subscription mode %s", viper.GetString("stream-subscription-mode"))
			}
			subscriptions[i].Mode = gnmi.SubscriptionMode(mode)
			switch gnmi.SubscriptionMode(mode) {
			case gnmi.SubscriptionMode_ON_CHANGE:
				subscriptions[i].HeartbeatInterval = uint64(heartbeatInterval.Nanoseconds())
			case gnmi.SubscriptionMode_SAMPLE:
				subscriptions[i].SampleInterval = uint64(samplingInterval.Nanoseconds())
				subscriptions[i].SuppressRedundant = viper.GetBool("suppress-redundant")
				if subscriptions[i].SuppressRedundant {
					subscriptions[i].HeartbeatInterval = uint64(heartbeatInterval.Nanoseconds())
				}
			case gnmi.SubscriptionMode_TARGET_DEFINED:
				subscriptions[i].SampleInterval = uint64(samplingInterval.Nanoseconds())
				subscriptions[i].SuppressRedundant = viper.GetBool("suppress-redundant")
				if subscriptions[i].SuppressRedundant {
					subscriptions[i].HeartbeatInterval = uint64(heartbeatInterval.Nanoseconds())
				}
			}
		}
	}
	model := viper.GetString("sub-model")
	models := make([]*gnmi.ModelData, 1)
	if model != "" {
		models[0] = &gnmi.ModelData{Name: model}
		return &gnmi.SubscribeRequest{
			Request: &gnmi.SubscribeRequest_Subscribe{
				Subscribe: &gnmi.SubscriptionList{
					Prefix:       gnmiPrefix,
					Mode:         gnmi.SubscriptionList_Mode(modeVal),
					Encoding:     gnmi.Encoding(encodingVal),
					Subscription: subscriptions,
					UseModels:    models,
					Qos:          qos,
					UpdatesOnly:  viper.GetBool("updates-only"),
				},
			},
		}, nil

	}
	return &gnmi.SubscribeRequest{
		Request: &gnmi.SubscribeRequest_Subscribe{
			Subscribe: &gnmi.SubscriptionList{
				Prefix:       gnmiPrefix,
				Mode:         gnmi.SubscriptionList_Mode(modeVal),
				Encoding:     gnmi.Encoding(encodingVal),
				Subscription: subscriptions,
				//UseModels:    models,
				Qos:         qos,
				UpdatesOnly: viper.GetBool("updates-only"),
			},
		},
	}, nil
}

func printSubscribeResponse(meta map[string]interface{}, subResp *gnmi.SubscribeResponse) {
	switch resp := subResp.Response.(type) {
	case *gnmi.SubscribeResponse_Update:
		if viper.GetString("format") == "textproto" {
			fmt.Printf("%s\n", proto.MarshalTextString(subResp))
			return
		}
		msg := new(msg)
		msg.Timestamp = resp.Update.Timestamp
		t := time.Unix(0, resp.Update.Timestamp)
		msg.Time = &t
		if meta == nil {
			meta = make(map[string]interface{})
		}
		msg.Prefix = gnmiPathToXPath(resp.Update.Prefix)
		var ok bool
		if _, ok = meta["source"]; ok {
			msg.Source = fmt.Sprintf("%s", meta["source"])
		}
		if _, ok = meta["system-name"]; ok {
			msg.SystemName = fmt.Sprintf("%s", meta["system-name"])
		}
		if _, ok = meta["subscription-name"]; ok {
			msg.SubscriptionName = fmt.Sprintf("%s", meta["subscription-name"])
		}
		for i, upd := range resp.Update.Update {
			pathElems := make([]string, 0, len(upd.Path.Elem))
			for _, pElem := range upd.Path.Elem {
				pathElems = append(pathElems, pElem.GetName())
			}
			value, err := getValue(upd.Val)
			if err != nil {
				logger.Println(err)
			}

			msg.Updates = append(msg.Updates,
				&update{
					Path:   gnmiPathToXPath(upd.Path),
					Values: make(map[string]interface{}),
				})
			msg.Updates[i].Values[strings.Join(pathElems, "/")] = value
		}
		for _, del := range resp.Update.Delete {
			msg.Deletes = append(msg.Deletes, gnmiPathToXPath(del))
		}
		data, err := json.MarshalIndent(msg, "", "  ")
		if err != nil {
			logger.Println(err)
		}
		fmt.Printf("%s\n", string(data))
	}
}
