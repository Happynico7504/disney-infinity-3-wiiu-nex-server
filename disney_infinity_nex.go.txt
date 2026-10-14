package main

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"

	nexgo "github.com/PretendoNetwork/nex-go/v2"
	"github.com/PretendoNetwork/nex-go/v2/types"
	common_globals "github.com/PretendoNetwork/nex-protocols-common-go/v2/globals"
	common_matchmaking "github.com/PretendoNetwork/nex-protocols-common-go/v2/match-making"
	common_matchmaking_ext "github.com/PretendoNetwork/nex-protocols-common-go/v2/match-making-ext"
	common_matchmake_extension "github.com/PretendoNetwork/nex-protocols-common-go/v2/matchmake-extension"
	common_nat_traversal "github.com/PretendoNetwork/nex-protocols-common-go/v2/nat-traversal"
	common_secure "github.com/PretendoNetwork/nex-protocols-common-go/v2/secure-connection"
	common_ticket_granting "github.com/PretendoNetwork/nex-protocols-common-go/v2/ticket-granting"
	common_utility "github.com/PretendoNetwork/nex-protocols-common-go/v2/utility"
	matchmaking "github.com/PretendoNetwork/nex-protocols-go/v2/match-making"
	matchmaking_ext "github.com/PretendoNetwork/nex-protocols-go/v2/match-making-ext"
	matchmaking_types "github.com/PretendoNetwork/nex-protocols-go/v2/match-making/types"
	matchmake_extension "github.com/PretendoNetwork/nex-protocols-go/v2/matchmake-extension"
	nat_traversal "github.com/PretendoNetwork/nex-protocols-go/v2/nat-traversal"
	secure "github.com/PretendoNetwork/nex-protocols-go/v2/secure-connection"
	ticket_granting "github.com/PretendoNetwork/nex-protocols-go/v2/ticket-granting"
	utility "github.com/PretendoNetwork/nex-protocols-go/v2/utility"
	_ "github.com/lib/pq"
)

const (
	AccessKey    = "83a601e5"
	GameServerID = 0x101AC900
)

var (
	authAccount   = nexgo.NewAccount(types.NewPID(1), "Quazal Authentication", "authpass", false)
	secureAccount = nexgo.NewAccount(types.NewPID(2), "Quazal Rendez-Vous", "securepass", false)
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func accountByPID(pid types.PID) (*nexgo.Account, *nexgo.Error) {
	switch uint64(pid) {
	case 1:
		return authAccount, nil
	case 2:
		return secureAccount, nil
	}
	return nexgo.NewAccount(pid, strconv.FormatUint(uint64(pid), 10), "playerpass", false), nil
}

func accountByName(name string) (*nexgo.Account, *nexgo.Error) {
	pid, err := strconv.ParseUint(name, 10, 64)
	if err != nil {
		return nil, nexgo.NewError(nexgo.ResultCodes.Core.InvalidArgument, "invalid username")
	}
	return accountByPID(types.NewPID(pid))
}

func newServer(endpoint *nexgo.PRUDPEndPoint, tag string) *nexgo.PRUDPServer {
	server := nexgo.NewPRUDPServer()
	server.BindPRUDPEndPoint(endpoint)
	server.LibraryVersions.SetDefault(nexgo.NewLibraryVersion(3, 9, 1))
	server.AccessKey = AccessKey
	server.ByteStreamSettings.UseStructureHeader = true

	endpoint.OnData(func(packet nexgo.PacketInterface) {
		request := packet.RMCMessage()
		if request == nil {
			return
		}
		fmt.Printf("[%s] PID=%d protocol=0x%02X method=0x%02X\n", tag, uint64(packet.Sender().PID()), request.ProtocolID, request.MethodID)
	})
	endpoint.OnConnectionEnded(func(connection *nexgo.PRUDPConnection) {
		fmt.Printf("[%s] PID=%d disconnected\n", tag, uint64(connection.PID()))
	})
	return server
}

func startAuth(host string, authPort, securePort int) {
	endpoint := nexgo.NewPRUDPEndPoint(1)
	endpoint.ServerAccount = authAccount
	endpoint.AccountDetailsByPID = accountByPID
	endpoint.AccountDetailsByUsername = accountByName
	server := newServer(endpoint, "Auth")

	protocol := ticket_granting.NewProtocol()
	endpoint.RegisterServiceProtocol(protocol)
	common := common_ticket_granting.NewCommonProtocol(protocol)

	secureURL := types.NewStationURL(types.String(fmt.Sprintf("prudps:/PID=2;sid=1;stream=10;type=2;address=%s;port=%d;CID=1", host, securePort)))
	common.SecureStationURL = secureURL
	common.BuildName = "Disney Infinity 3.0 Wii U"
	common.SecureServerAccount = secureAccount

	fmt.Printf("[Auth] listening on UDP %d\n", authPort)
	server.Listen(authPort)
}

func startSecure(host string, securePort int) {
	endpoint := nexgo.NewPRUDPEndPoint(1)
	endpoint.IsSecureEndPoint = true
	endpoint.ServerAccount = secureAccount
	endpoint.AccountDetailsByPID = accountByPID
	endpoint.AccountDetailsByUsername = accountByName
	server := newServer(endpoint, "Secure")

	secureProtocol := secure.NewProtocol()
	endpoint.RegisterServiceProtocol(secureProtocol)
	secureCommon := common_secure.NewCommonProtocol(secureProtocol)
	secureCommon.EnableInsecureRegister()
	secureCommon.CreateReportDBRecord = func(pid types.PID, reportID types.UInt32, reportData types.QBuffer) error {
		return nil
	}

	utilityProtocol := utility.NewProtocol()
	endpoint.RegisterServiceProtocol(utilityProtocol)
	common_utility.NewCommonProtocol(utilityProtocol)

	natProtocol := nat_traversal.NewProtocol()
	endpoint.RegisterServiceProtocol(natProtocol)
	common_nat_traversal.NewCommonProtocol(natProtocol)

	registerExtras(endpoint, host)

	if uri := os.Getenv("PN_POSTGRES_URI"); uri != "" {
		registerMatchmaking(endpoint, uri)
	} else {
		fmt.Println("[Secure] PN_POSTGRES_URI not set: matchmaking disabled, login and NAT traversal only")
	}

	fmt.Printf("[Secure] listening on UDP %d\n", securePort)
	server.Listen(securePort)
}

func registerMatchmaking(endpoint *nexgo.PRUDPEndPoint, uri string) {
	db, err := sql.Open("postgres", uri)
	if err != nil {
		fmt.Println("[Secure] postgres error:", err)
		return
	}
	manager := common_globals.NewMatchmakingManager(endpoint, db)
	manager.GetUserFriendPIDs = func(pid uint32) []uint32 { return nil }

	mmProtocol := matchmaking.NewProtocol()
	endpoint.RegisterServiceProtocol(mmProtocol)
	common_matchmaking.NewCommonProtocol(mmProtocol).SetManager(manager)

	mmExtProtocol := matchmaking_ext.NewProtocol()
	endpoint.RegisterServiceProtocol(mmExtProtocol)
	common_matchmaking_ext.NewCommonProtocol(mmExtProtocol).SetManager(manager)

	mmeProtocol := matchmake_extension.NewProtocol()
	endpoint.RegisterServiceProtocol(mmeProtocol)
	mmeCommon := common_matchmake_extension.NewCommonProtocol(mmeProtocol)
	mmeCommon.SetManager(manager)
	mmeCommon.CleanupMatchmakeSessionSearchCriterias = func(searchCriterias types.List[matchmaking_types.MatchmakeSessionSearchCriteria]) {}
	mmeCommon.CleanupSearchMatchmakeSession = func(matchmakeSession *matchmaking_types.MatchmakeSession) {}
}

func main() {
	host := env("NEX_HOST", "127.0.0.1")
	authPort, _ := strconv.Atoi(env("AUTH_PORT", "60000"))
	securePort, _ := strconv.Atoi(env("SECURE_PORT", "60001"))
	fmt.Printf("Disney Infinity 3.0 NEX: access key %s, game server id 0x%X, host %s\n", AccessKey, GameServerID, host)
	go startAuth(host, authPort, securePort)
	startSecure(host, securePort)
}
