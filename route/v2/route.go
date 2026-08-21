package v2

import codegen "github.com/EdmundFu-233/ReCasaOS-UserService/codegen/user_service"

type UserService struct{}

func NewUserService() codegen.ServerInterface {
	return &UserService{}
}
