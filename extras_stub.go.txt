//go:build !extras

package main

import nexgo "github.com/PretendoNetwork/nex-go/v2"

func registerExtras(endpoint *nexgo.PRUDPEndPoint, host string) {}
