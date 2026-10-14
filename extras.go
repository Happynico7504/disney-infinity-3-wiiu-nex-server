//go:build extras

package main

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	nexgo "github.com/PretendoNetwork/nex-go/v2"
	"github.com/PretendoNetwork/nex-go/v2/types"
	datastore "github.com/PretendoNetwork/nex-protocols-go/v2/datastore"
	datastore_types "github.com/PretendoNetwork/nex-protocols-go/v2/datastore/types"
)

const dataStorePort = 8765

type storedObject struct {
	id       uint64
	owner    uint64
	name     string
	dataType uint16
	meta     []byte
	flag     uint32
	data     []byte
	created  time.Time
	updated  time.Time
	complete bool
}

var (
	objectsMu sync.Mutex
	objects   = map[uint64]*storedObject{}
	nextID    uint64 = 1000
)

func okResponse(endpoint nexgo.EndpointInterface, callID uint32, method uint32, body []byte) *nexgo.RMCMessage {
	response := nexgo.NewRMCSuccess(endpoint, body)
	response.ProtocolID = datastore.ProtocolID
	response.MethodID = method
	response.CallID = callID
	return response
}

func metaInfo(o *storedObject) *datastore_types.DataStoreMetaInfo {
	meta := datastore_types.NewDataStoreMetaInfo()
	meta.DataID = types.NewUInt64(o.id)
	meta.OwnerID = types.NewPID(o.owner)
	meta.Size = types.NewUInt32(uint32(len(o.data)))
	meta.Name = types.NewString(o.name)
	meta.DataType = types.NewUInt16(o.dataType)
	meta.MetaBinary = types.NewQBuffer(o.meta)
	meta.Period = types.NewUInt16(365)
	meta.Status = types.NewUInt8(0)
	meta.Flag = types.NewUInt32(o.flag)
	meta.CreatedTime = types.NewDateTime(0).FromTimestamp(o.created)
	meta.UpdatedTime = types.NewDateTime(0).FromTimestamp(o.updated)
	return meta
}

func registerExtras(endpoint *nexgo.PRUDPEndPoint, host string) {
	protocol := datastore.NewProtocol()
	endpoint.RegisterServiceProtocol(protocol)
	base := fmt.Sprintf("http://%s:%d", host, dataStorePort)

	protocol.SetHandlerPreparePostObject(func(err error, packet nexgo.PacketInterface, callID uint32, param *datastore_types.DataStorePreparePostParam) (*nexgo.RMCMessage, *nexgo.Error) {
		if err != nil {
			return nil, nexgo.NewError(nexgo.ResultCodes.Core.InvalidArgument, err.Error())
		}
		connection := packet.Sender().(*nexgo.PRUDPConnection)
		objectsMu.Lock()
		nextID++
		id := nextID
		objects[id] = &storedObject{id: id, owner: uint64(connection.PID()), name: string(param.Name), dataType: uint16(param.DataType),
			meta: []byte(param.MetaBinary), flag: uint32(param.Flag), created: time.Now(), updated: time.Now()}
		objectsMu.Unlock()

		info := datastore_types.NewDataStoreReqPostInfo()
		info.DataID = types.NewUInt64(id)
		info.URL = types.NewString(fmt.Sprintf("%s/ds/%d", base, id))
		info.RequestHeaders = types.NewList[datastore_types.DataStoreKeyValue]()
		info.FormFields = types.NewList[datastore_types.DataStoreKeyValue]()
		info.RootCACert = types.NewBuffer(nil)

		stream := nexgo.NewByteStreamOut(endpoint.LibraryVersions(), endpoint.ByteStreamSettings())
		info.WriteTo(stream)
		return okResponse(endpoint, callID, datastore.MethodPreparePostObject, stream.Bytes()), nil
	})

	protocol.SetHandlerCompletePostObject(func(err error, packet nexgo.PacketInterface, callID uint32, param *datastore_types.DataStoreCompletePostParam) (*nexgo.RMCMessage, *nexgo.Error) {
		if err != nil {
			return nil, nexgo.NewError(nexgo.ResultCodes.Core.InvalidArgument, err.Error())
		}
		objectsMu.Lock()
		if o := objects[uint64(param.DataID)]; o != nil {
			o.complete = bool(param.IsSuccess)
		}
		objectsMu.Unlock()
		return okResponse(endpoint, callID, datastore.MethodCompletePostObject, nil), nil
	})

	protocol.SetHandlerPrepareGetObject(func(err error, packet nexgo.PacketInterface, callID uint32, param *datastore_types.DataStorePrepareGetParam) (*nexgo.RMCMessage, *nexgo.Error) {
		if err != nil {
			return nil, nexgo.NewError(nexgo.ResultCodes.Core.InvalidArgument, err.Error())
		}
		objectsMu.Lock()
		o := objects[uint64(param.DataID)]
		objectsMu.Unlock()
		if o == nil {
			return nil, nexgo.NewError(nexgo.ResultCodes.DataStore.NotFound, "object not found")
		}
		info := datastore_types.NewDataStoreReqGetInfo()
		info.URL = types.NewString(fmt.Sprintf("%s/ds/%d", base, o.id))
		info.RequestHeaders = types.NewList[datastore_types.DataStoreKeyValue]()
		info.Size = types.NewUInt32(uint32(len(o.data)))
		info.RootCACert = types.NewBuffer(nil)
		info.DataID = types.NewUInt64(o.id)

		stream := nexgo.NewByteStreamOut(endpoint.LibraryVersions(), endpoint.ByteStreamSettings())
		info.WriteTo(stream)
		return okResponse(endpoint, callID, datastore.MethodPrepareGetObject, stream.Bytes()), nil
	})

	protocol.SetHandlerGetMeta(func(err error, packet nexgo.PacketInterface, callID uint32, param *datastore_types.DataStoreGetMetaParam) (*nexgo.RMCMessage, *nexgo.Error) {
		if err != nil {
			return nil, nexgo.NewError(nexgo.ResultCodes.Core.InvalidArgument, err.Error())
		}
		objectsMu.Lock()
		o := objects[uint64(param.DataID)]
		objectsMu.Unlock()
		if o == nil {
			return nil, nexgo.NewError(nexgo.ResultCodes.DataStore.NotFound, "object not found")
		}
		stream := nexgo.NewByteStreamOut(endpoint.LibraryVersions(), endpoint.ByteStreamSettings())
		metaInfo(o).WriteTo(stream)
		return okResponse(endpoint, callID, datastore.MethodGetMeta, stream.Bytes()), nil
	})

	protocol.SetHandlerPostMetaBinary(func(err error, packet nexgo.PacketInterface, callID uint32, param *datastore_types.DataStorePreparePostParam) (*nexgo.RMCMessage, *nexgo.Error) {
		if err != nil {
			return nil, nexgo.NewError(nexgo.ResultCodes.Core.InvalidArgument, err.Error())
		}
		connection := packet.Sender().(*nexgo.PRUDPConnection)
		owner := uint64(connection.PID())
		objectsMu.Lock()
		var id uint64
		for _, o := range objects {
			if o.owner == owner && o.dataType == uint16(param.DataType) && len(o.data) == 0 {
				id = o.id
			}
		}
		if id == 0 {
			nextID++
			id = nextID
		}
		objects[id] = &storedObject{id: id, owner: owner, name: string(param.Name), dataType: uint16(param.DataType),
			meta: []byte(param.MetaBinary), flag: uint32(param.Flag), complete: true, created: time.Now(), updated: time.Now()}
		objectsMu.Unlock()

		stream := nexgo.NewByteStreamOut(endpoint.LibraryVersions(), endpoint.ByteStreamSettings())
		types.NewUInt64(id).WriteTo(stream)
		return okResponse(endpoint, callID, datastore.MethodPostMetaBinary, stream.Bytes()), nil
	})

	protocol.SetHandlerChangeMeta(func(err error, packet nexgo.PacketInterface, callID uint32, param *datastore_types.DataStoreChangeMetaParam) (*nexgo.RMCMessage, *nexgo.Error) {
		if err != nil {
			return nil, nexgo.NewError(nexgo.ResultCodes.Core.InvalidArgument, err.Error())
		}
		objectsMu.Lock()
		if o := objects[uint64(param.DataID)]; o != nil {
			if len(param.MetaBinary) > 0 {
				o.meta = []byte(param.MetaBinary)
			}
			o.updated = time.Now()
		}
		objectsMu.Unlock()
		return okResponse(endpoint, callID, datastore.MethodChangeMeta, nil), nil
	})

	protocol.SetHandlerSearchObject(func(err error, packet nexgo.PacketInterface, callID uint32, param *datastore_types.DataStoreSearchParam) (*nexgo.RMCMessage, *nexgo.Error) {
		if err != nil {
			return nil, nexgo.NewError(nexgo.ResultCodes.Core.InvalidArgument, err.Error())
		}
		result := datastore_types.NewDataStoreSearchResult()
		result.Result = types.NewList[datastore_types.DataStoreMetaInfo]()
		objectsMu.Lock()
		for _, o := range objects {
			if !o.complete {
				continue
			}
			if uint16(param.DataType) != 0 && o.dataType != uint16(param.DataType) {
				continue
			}
			if uint64(param.OwnerID) != 0 && o.owner != uint64(param.OwnerID) {
				continue
			}
			result.Result = append(result.Result, *metaInfo(o))
		}
		objectsMu.Unlock()
		result.TotalCount = types.NewUInt32(uint32(len(result.Result)))
		result.TotalCountType = types.NewUInt8(0)

		stream := nexgo.NewByteStreamOut(endpoint.LibraryVersions(), endpoint.ByteStreamSettings())
		result.WriteTo(stream)
		return okResponse(endpoint, callID, datastore.MethodSearchObject, stream.Bytes()), nil
	})

	go serveObjects()
}

func serveObjects() {
	mux := http.NewServeMux()
	mux.HandleFunc("/ds/", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseUint(strings.TrimPrefix(r.URL.Path, "/ds/"), 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		objectsMu.Lock()
		o := objects[id]
		objectsMu.Unlock()
		if o == nil {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodPost, http.MethodPut:
			var body []byte
			if reader, err := r.MultipartReader(); err == nil {
				for {
					part, err := reader.NextPart()
					if err != nil {
						break
					}
					if part.FormName() == "file" {
						body, _ = io.ReadAll(part)
					}
				}
			} else {
				body, _ = io.ReadAll(r.Body)
			}
			objectsMu.Lock()
			o.data, o.updated = body, time.Now()
			objectsMu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			objectsMu.Lock()
			data := o.data
			objectsMu.Unlock()
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(data)
		}
	})
	http.ListenAndServe(fmt.Sprintf(":%d", dataStorePort), mux)
}
