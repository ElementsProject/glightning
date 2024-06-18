package main

import (
	"log"
	"os"

	"github.com/elementsproject/glightning/glightning"
	"github.com/elementsproject/glightning/jrpc2"
)

func main() {
	plugin := glightning.NewPlugin(onInit)
	plugin.RegisterHooks(&glightning.Hooks{
		RpcCommand: OnRpcCommand,
	})

	err := plugin.Start(os.Stdin, os.Stdout)
	if err != nil {
		log.Fatal(err)
	}
}

func onInit(plugin *glightning.Plugin, options map[string]glightning.Option, config *glightning.Config) {
	log.Printf("successfully init'd! %s\n", config.RpcFile)
}

func OnRpcCommand(event *glightning.RpcCommandEvent) (*jrpc2.RpcCommandResponse, error) {
	cmd := event.Cmd
	id, _ := cmd.Id()
	log.Printf("command %s called id %s", cmd.MethodName, id)

	method, err := cmd.Get()
	if err != nil {
		return nil, err
	}

	// only return bech32 addresses for new addr
	if nar, ok := method.(*glightning.NewAddrRequest); ok {
		return handleNewAddrRequest(event, nar)
	}

	// don't let anyone withdraw anything
	if _, ok := method.(*glightning.WithdrawRequest); ok {
		return event.ReturnError("withdrawals not allowed", -401)
	}

	if _, ok := method.(*glightning.PingRequest); ok {
		return event.ReturnResult("bullseye!")
	}

	return event.Continue(), nil
}

func handleNewAddrRequest(event *glightning.RpcCommandEvent, req *glightning.NewAddrRequest) (*jrpc2.RpcCommandResponse, error) {
	// alway set address type to bech32
	req.AddressType = "bech32"

	return event.ReplaceWith(req), nil
}
