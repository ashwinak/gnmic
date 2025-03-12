package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	spb "github.com/openconfig/gribi/v1/proto/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/prototext"
)

var (
	dirToParse        = "./get-before-rpd-restart"
	responseSuffix    = "GetResponse.textproto"
	serverAddr        = "[2607:f8b0:f803:160b::1]:9340"
	tls_flag          = false
	cred_meta         = map[string]string{"username": "admin", "password": "admin"}
	client_cert_file  = "/vmm/data/gnsi_experiments/intermediate-test/client-cert.pem"
	client_key_file   = "/vmm/data/gnsi_experiments/intermediate-test/client-key.pem"
	trust_bundle_file = "/vmm/data/gnsi_experiments/intermediate-test/trust-bundle-a.pem"
	skip_verify_flag  = true
	SAN               = "role001.pop55.net.example.com"
	OPStartIndex      = uint64(1)
	electionIdH       = uint64(1733594965)
	electionidL       = uint64(28198809907424407)

	nhgList     = map[uint64]*nhg{}
	nhList      = map[uint64]*nh{}
	prefixList  = map[string]map[string]*prefix{} //map[route-table]map[prefix]*prefix
	orderedOps  = []*spb.AFTOperation{}
	OPCurrIndex = OPStartIndex
)

type nh struct {
	index      uint64
	rawMessage *spb.AFTEntry
}
type nhg struct {
	index       uint64
	nh          map[uint64]*nh
	nhList      []uint64
	weights     map[uint64]uint
	backup      *nhg
	backupIndex uint64
	rawMessage  *spb.AFTEntry
}
type prefix struct {
	routeTable string
	prefix     string
	nhg        *nhg
	nhgIndex   uint64
	rawMessage *spb.AFTEntry
}

type Cred struct {
	username string
	password string
	tls      bool
}

// GetRequestMetadata is needed by credentials.PerRPCCredentials.
func (s Cred) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	// We can pass any metadata to the server here
	return map[string]string{
		"username": s.username,
		"password": s.password,
	}, nil
}

// RequireTransportSecurity is needed by credentials.PerRPCCredentials.
func (s Cred) RequireTransportSecurity() bool {
	return s.tls
}

func parseResponses(responseFiles []string) {

	for _, responseFile := range responseFiles {

		file, err := os.Open(dirToParse + "/" + responseFile)
		if err != nil {
			log.Printf("couldn't open response file: %s", responseFile)
			break
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}

		if err := scanner.Err(); err != nil {
			log.Printf("couldn't get lines from file: %s", responseFile)
			break
		}

		// Exclude first and last two lines
		if len(lines) > 5 {
			lines = lines[3 : len(lines)-2]
		}

		// join the remaining lines
		responseProtoText := strings.Join(lines, "\n")

		responseMessage := &spb.GetResponse{}

		if err = prototext.Unmarshal([]byte(responseProtoText), responseMessage); err != nil {
			log.Printf("couldn't umarshal request in: %s, %s", responseFile, responseProtoText)
			break
		}

		if entries := responseMessage.GetEntry(); len(entries) > 0 {

			for _, entry := range entries {

				if entryContent := entry.GetIpv4(); entryContent != nil {

					ni := entry.GetNetworkInstance()
					if ni == "" {
						ni = "DEFAULT"
					}
					if _, ok := prefixList[ni]; !ok {
						prefixList[ni] = map[string]*prefix{}
					}
					prefixList[ni][entryContent.GetPrefix()] = &prefix{routeTable: ni, prefix: entryContent.GetPrefix(), nhgIndex: entryContent.GetIpv4Entry().GetNextHopGroup().GetValue(), rawMessage: entry}

				} else if entryContent := entry.GetNextHop(); entryContent != nil {
					nhList[entry.GetNextHop().GetIndex()] = &nh{index: entry.GetNextHop().GetIndex(), rawMessage: entry}

				} else if entryContent := entry.GetNextHopGroup(); entryContent != nil {
					nhList := []uint64{}
					weightsMap := map[uint64]uint{}
					for _, nh := range entryContent.GetNextHopGroup().GetNextHop() {
						nhList = append(nhList, nh.GetIndex())
						weightsMap[nh.GetIndex()] = uint(nh.GetNextHop().GetWeight().GetValue())
					}
					backupNhgIndex := uint64(0)
					if entryContent.GetNextHopGroup().GetBackupNextHopGroup() != nil {
						backupNhgIndex = entryContent.GetNextHopGroup().GetBackupNextHopGroup().GetValue()
					}
					nhgList[entryContent.GetId()] = &nhg{index: entryContent.GetId(), nhList: nhList, weights: weightsMap, backupIndex: backupNhgIndex, rawMessage: entry}

				}

			}
		}

	}

}

func resolveNHG() {
	for id, nhg := range nhgList {
		for _, index := range nhg.nhList {
			if nhObj, ok := nhList[index]; ok {
				if nhg.nh == nil {
					nhg.nh = map[uint64]*nh{}
				}
				nhg.nh[index] = nhObj
			} else {
				log.Printf("NH %d doesn't exist.Cannot fully resolve NHG %d\n", index, id)
			}

		}
	}
	for id, nhg := range nhgList {
		if nhg.backupIndex != uint64(0) {
			if nhObj, ok := nhgList[nhg.backupIndex]; ok {
				nhg.backup = nhObj
			} else {
				log.Printf("Backup NHG %d doesn't exist.Cannot fully resolve NHG %d\n", nhg.backupIndex, id)
			}

		}
	}
}

func resolvePrefix() {
	for tableName, tableEntries := range prefixList {
		for p, pObj := range tableEntries {
			if nhg, ok := nhgList[pObj.nhgIndex]; ok {
				pObj.nhg = nhg
			} else {
				log.Printf("NHG %d doesn't exist.Cannot fully resolve Prefix %s in routing table %s\n", pObj.nhgIndex, p, tableName)
			}
		}
	}
}

func resolveNhAddress(ipAddress string) {

	if p, ok := prefixList["DEFAULT"][ipAddress]; ok {

		for _, nh := range p.nhg.nh {

			if nh.rawMessage.GetNextHop().GetNextHop().GetIpAddress() != nil && nh.rawMessage.GetNextHop().GetNextHop().GetInterfaceRef() == nil {

				resolveNhAddress(nh.rawMessage.GetNextHop().GetNextHop().GetIpAddress().GetValue() + "/32")

			} else {

				orderedOps = append(orderedOps, &spb.AFTOperation{Id: OPCurrIndex, Op: spb.AFTOperation_ADD, NetworkInstance: "DEFAULT", Entry: &spb.AFTOperation_NextHop{NextHop: nh.rawMessage.GetNextHop()}, ElectionId: &spb.Uint128{High: electionIdH, Low: electionidL}})
				OPCurrIndex += 1
			}

		}
		if p.nhg.backup != nil {
			orderedOps = append(orderedOps, &spb.AFTOperation{Id: OPCurrIndex, Op: spb.AFTOperation_ADD, NetworkInstance: "DEFAULT", Entry: &spb.AFTOperation_NextHopGroup{NextHopGroup: p.nhg.backup.rawMessage.GetNextHopGroup()}, ElectionId: &spb.Uint128{High: electionIdH, Low: electionidL}})
			OPCurrIndex += 1
		}
		orderedOps = append(orderedOps, &spb.AFTOperation{Id: OPCurrIndex, Op: spb.AFTOperation_ADD, NetworkInstance: "DEFAULT", Entry: &spb.AFTOperation_NextHopGroup{NextHopGroup: p.nhg.rawMessage.GetNextHopGroup()}, ElectionId: &spb.Uint128{High: electionIdH, Low: electionidL}})
		OPCurrIndex += 1
		orderedOps = append(orderedOps, &spb.AFTOperation{Id: OPCurrIndex, Op: spb.AFTOperation_ADD, NetworkInstance: "DEFAULT", Entry: &spb.AFTOperation_Ipv4{Ipv4: p.rawMessage.GetIpv4()}, ElectionId: &spb.Uint128{High: electionIdH, Low: electionidL}})
		OPCurrIndex += 1

	} else {
		log.Printf("Could not find prefix %s in DEFAULT instance", ipAddress)
	}

}

func buildOrderedList() {

	for _, nextHop := range nhList {

		if nextHop.rawMessage.GetNextHop().GetNextHop().GetIpAddress() != nil && nextHop.rawMessage.GetNextHop().GetNextHop().GetInterfaceRef() == nil {

			resolveNhAddress(nextHop.rawMessage.GetNextHop().GetNextHop().GetIpAddress().GetValue() + "/32")
			orderedOps = append(orderedOps, &spb.AFTOperation{Id: OPCurrIndex, Op: spb.AFTOperation_ADD, NetworkInstance: "DEFAULT", Entry: &spb.AFTOperation_NextHop{NextHop: nextHop.rawMessage.GetNextHop()}, ElectionId: &spb.Uint128{High: electionIdH, Low: electionidL}})
			OPCurrIndex += 1

		} else {

			orderedOps = append(orderedOps, &spb.AFTOperation{Id: OPCurrIndex, Op: spb.AFTOperation_ADD, NetworkInstance: "DEFAULT", Entry: &spb.AFTOperation_NextHop{NextHop: nextHop.rawMessage.GetNextHop()}, ElectionId: &spb.Uint128{High: electionIdH, Low: electionidL}})
			OPCurrIndex += 1
		}

	}
	for _, nhg := range nhgList {
		if nhg.backup != nil {
			orderedOps = append(orderedOps, &spb.AFTOperation{Id: OPCurrIndex, Op: spb.AFTOperation_ADD, NetworkInstance: "DEFAULT", Entry: &spb.AFTOperation_NextHopGroup{NextHopGroup: nhg.backup.rawMessage.GetNextHopGroup()}, ElectionId: &spb.Uint128{High: electionIdH, Low: electionidL}})
			OPCurrIndex += 1
		}
		orderedOps = append(orderedOps, &spb.AFTOperation{Id: OPCurrIndex, Op: spb.AFTOperation_ADD, NetworkInstance: "DEFAULT", Entry: &spb.AFTOperation_NextHopGroup{NextHopGroup: nhg.rawMessage.GetNextHopGroup()}, ElectionId: &spb.Uint128{High: electionIdH, Low: electionidL}})
		OPCurrIndex += 1
	}
	for instance, tableEntries := range prefixList {

		for _, prefix := range tableEntries {

			orderedOps = append(orderedOps, &spb.AFTOperation{Id: OPCurrIndex, Op: spb.AFTOperation_ADD, NetworkInstance: instance, Entry: &spb.AFTOperation_Ipv4{Ipv4: prefix.rawMessage.GetIpv4()}, ElectionId: &spb.Uint128{High: electionIdH, Low: electionidL}})
			OPCurrIndex += 1
		}
	}

}

func ReadResponse(gribiClient spb.GRIBI_ModifyClient) {

	ops := map[uint64]spb.AFTResult_Status{}
	for _, op := range orderedOps {
		ops[op.GetId()] = spb.AFTResult_UNSET
	}
	for {
		response, err := gribiClient.Recv()

		if err != nil {
			if err == io.EOF {

				log.Fatalf("Error reading gribi modify response: %v", err)
			}
		}

		results := []string{}
		for _, result := range response.GetResult() {

			switch result.GetStatus() {
			case spb.AFTResult_FAILED:
				ops[result.GetId()] = spb.AFTResult_FAILED
				results = append(results, fmt.Sprintf("%d-%s", result.GetId(), result.GetStatus()))
				for _, op := range orderedOps {
					if op.Id == result.GetId() {
						log.Printf("FAILED status for Operation: %d with message: %s. Op = %v", result.GetId(), result.GetErrorDetails().GetErrorMessage(), op)
						//log.Printf("nh: %v\n", nhList[op.GetNextHopGroup().GetNextHopGroup().GetNextHop()[0].GetIndex()])
					}
				}
			case spb.AFTResult_FIB_FAILED:
				ops[result.GetId()] = spb.AFTResult_FIB_FAILED
				results = append(results, fmt.Sprintf("%d-%s", result.GetId(), result.GetStatus()))
				for _, op := range orderedOps {
					if op.Id == result.GetId() {
						log.Printf("FIB_FAILED status for Operation: %d with message: %s. Op = %v", result.GetId(), result.GetErrorDetails().GetErrorMessage(), op)
					}
				}
			case spb.AFTResult_FIB_PROGRAMMED:
				ops[result.GetId()] = spb.AFTResult_FIB_PROGRAMMED
				results = append(results, fmt.Sprintf("%d-%s", result.GetId(), result.GetStatus()))
			case spb.AFTResult_RIB_PROGRAMMED:
				ops[result.GetId()] = spb.AFTResult_RIB_PROGRAMMED
				results = append(results, fmt.Sprintf("%d-%s", result.GetId(), result.GetStatus()))
			default:
				results = append(results, fmt.Sprintf("%d-%s", result.GetId(), result.GetStatus()))
			}

		}
		log.Printf("Processed requests: %v", results)
		opsPending := false
		for _, status := range ops {
			if status == spb.AFTResult_UNSET {
				opsPending = true
			}
		}
		if !opsPending {
			log.Printf("Received reply for all %d operations.\n", len(ops))
			return
		}

		time.Sleep(50 * time.Millisecond)
	}
}

func sendRequests(requests []*spb.ModifyRequest) {

	var opts []grpc.DialOption

	if tls_flag {
		cert, err := tls.LoadX509KeyPair(client_cert_file, client_key_file)
		if err != nil {
			log.Fatalf("failed to load client cert: %v", err)
		}

		trust := x509.NewCertPool()
		trustBytes, err := os.ReadFile(trust_bundle_file)
		if err != nil {
			log.Fatalf("failed to read trust bundle %v: %v", trust_bundle_file, err)
		}
		if ok := trust.AppendCertsFromPEM(trustBytes); !ok {
			log.Fatalf("failed to parse %v", trust_bundle_file)
		}

		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: trust, ServerName: SAN, InsecureSkipVerify: skip_verify_flag})))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	opts = append(opts, grpc.WithPerRPCCredentials(Cred{username: cred_meta["username"], password: cred_meta["password"], tls: tls_flag}))

	conn, err := grpc.NewClient(serverAddr, opts...)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()

	local_context := context.Background()

	g := spb.NewGRIBIClient(conn)
	gribiClient, err := g.Modify(local_context)
	if err != nil {
		log.Fatalf("failed to create gribi modify client: %v", err)
	}

	paramsRequest := &spb.ModifyRequest{Params: &spb.SessionParameters{Redundancy: spb.SessionParameters_SINGLE_PRIMARY,
		Persistence: spb.SessionParameters_PRESERVE,
		AckType:     spb.SessionParameters_RIB_AND_FIB_ACK}}

	electionRequest := &spb.ModifyRequest{ElectionId: &spb.Uint128{High: electionIdH, Low: electionidL}}
	if err := gribiClient.Send(paramsRequest); err != nil {
		log.Fatalf("Couldn't send session parameters: %v", err)
	}
	if err := gribiClient.Send(electionRequest); err != nil {
		log.Fatalf("Couldn't send election id: %v", err)
	}

	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		defer wg.Done()
		ReadResponse(gribiClient)
	}()

	for _, request := range requests {

		//log.Printf("%v\n", request)

		if err := gribiClient.Send(request); err != nil {
			log.Fatalf("Error sending gribi modify request: %v. Error: %v", request, err)

		}
		time.Sleep(50 * time.Millisecond)
	}
	log.Printf("Finished sending %d Modify Requests for %d AFTOperations.\n", len(requests), len(orderedOps))
	wg.Wait()
}

func main() {

	files, err := os.ReadDir(dirToParse)
	if err != nil {
		panic(err)
	}
	responseFiles := []string{}
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), responseSuffix) {
			responseFiles = append(responseFiles, file.Name())
		}
	}
	byName := func(i, j int) bool { return responseFiles[i] < responseFiles[j] }
	sort.Slice(responseFiles, byName)

	parseResponses(responseFiles)
	resolveNHG()
	resolvePrefix()
	buildOrderedList()
	requests := []*spb.ModifyRequest{}
	for i := 0; i < len(orderedOps); i += 8 {

		end := i + 8
		if end > len(orderedOps) {
			end = len(orderedOps)
		}
		ops := orderedOps[i:end]
		requests = append(requests, &spb.ModifyRequest{Operation: ops})
	}

	sendRequests(requests)

}
