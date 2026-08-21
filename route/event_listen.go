package route

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	message_bus "github.com/EdmundFu-233/ReCasaOS-UserService/codegen/message_bus"
	"github.com/EdmundFu-233/ReCasaOS-UserService/model"
	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/config"
	"github.com/EdmundFu-233/ReCasaOS-UserService/service"
	"github.com/IceWhaleTech/CasaOS-Common/external"
	"github.com/IceWhaleTech/CasaOS-Common/utils/logger"
	"go.uber.org/zap"
	"golang.org/x/net/websocket"
)

func EventListen() {
	for i := 0; i < 1000; i++ {

		messageBusUrl, err := external.GetMessageBusAddress(config.CommonInfo.RuntimePath)
		if err != nil {
			logger.Error("get message bus url error", zap.Any("err", err))
			return
		}

		wsURL := fmt.Sprintf("ws://%s/event/%s", strings.ReplaceAll(messageBusUrl, "http://", ""), "local-storage")
		ws, err := websocket.Dial(wsURL, "", "http://localhost")
		if err != nil {
			logger.Error("connect websocket err"+strconv.Itoa(i), zap.Any("error", err))
			time.Sleep(time.Second * 1)
			continue
		}
		defer ws.Close()

		logger.Info("subscribed to", zap.Any("url", wsURL))
		for {

			msg := make([]byte, 1024)
			n, err := ws.Read(msg)
			if err != nil {
				logger.Error("err", zap.Any("err", err.Error()))
			}

			var event message_bus.Event

			if err := json.Unmarshal(msg[:n], &event); err != nil {
				logger.Error("err", zap.Any("err", err.Error()))
			}
			propertiesStr, err := json.Marshal(event.Properties)
			if err != nil {
				logger.Error("marshal error", zap.Any("err", err.Error()), zap.Any("event", event))
				continue
			}
			model := model.EventModel{
				SourceID:   event.SourceID,
				Name:       event.Name,
				Properties: string(propertiesStr),
				UUID:       *event.Uuid,
			}
			if event.Name == "local-storage:raid_status" {
				continue
			}
			service.MyService.Event().CreateEvemt(model)
			// logger.Info("info", zap.Any("写入信息1", model))
			// output, err := json.MarshalIndent(event, "", "  ")
			// if err != nil {
			// 	logger.Error("err", zap.Any("err", err.Error()))
			// }
			// logger.Info("info", zap.Any("写入信息", string(output)))
		}
	}
	logger.Error("error when try to connect to message bus")
}
