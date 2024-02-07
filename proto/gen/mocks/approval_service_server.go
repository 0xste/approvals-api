// Code generated by mockery v2.40.1. DO NOT EDIT.

package mock_proto

import (
	context "context"

	proto "github.com/0xste/approvals-api/proto/gen"
	mock "github.com/stretchr/testify/mock"
)

// Mockapproval_service_server is an autogenerated mock type for the ApprovalServiceServer type
type Mockapproval_service_server struct {
	mock.Mock
}

type Mockapproval_service_server_Expecter struct {
	mock *mock.Mock
}

func (_m *Mockapproval_service_server) EXPECT() *Mockapproval_service_server_Expecter {
	return &Mockapproval_service_server_Expecter{mock: &_m.Mock}
}

// ApproveApproval provides a mock function with given fields: _a0, _a1
func (_m *Mockapproval_service_server) ApproveApproval(_a0 context.Context, _a1 *proto.ApproveApprovalRequest) (*proto.ApproveApprovalResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for ApproveApproval")
	}

	var r0 *proto.ApproveApprovalResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *proto.ApproveApprovalRequest) (*proto.ApproveApprovalResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *proto.ApproveApprovalRequest) *proto.ApproveApprovalResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*proto.ApproveApprovalResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *proto.ApproveApprovalRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Mockapproval_service_server_ApproveApproval_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ApproveApproval'
type Mockapproval_service_server_ApproveApproval_Call struct {
	*mock.Call
}

// ApproveApproval is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *proto.ApproveApprovalRequest
func (_e *Mockapproval_service_server_Expecter) ApproveApproval(_a0 interface{}, _a1 interface{}) *Mockapproval_service_server_ApproveApproval_Call {
	return &Mockapproval_service_server_ApproveApproval_Call{Call: _e.mock.On("ApproveApproval", _a0, _a1)}
}

func (_c *Mockapproval_service_server_ApproveApproval_Call) Run(run func(_a0 context.Context, _a1 *proto.ApproveApprovalRequest)) *Mockapproval_service_server_ApproveApproval_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*proto.ApproveApprovalRequest))
	})
	return _c
}

func (_c *Mockapproval_service_server_ApproveApproval_Call) Return(_a0 *proto.ApproveApprovalResponse, _a1 error) *Mockapproval_service_server_ApproveApproval_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Mockapproval_service_server_ApproveApproval_Call) RunAndReturn(run func(context.Context, *proto.ApproveApprovalRequest) (*proto.ApproveApprovalResponse, error)) *Mockapproval_service_server_ApproveApproval_Call {
	_c.Call.Return(run)
	return _c
}

// CreateApproval provides a mock function with given fields: _a0, _a1
func (_m *Mockapproval_service_server) CreateApproval(_a0 context.Context, _a1 *proto.CreateApprovalRequest) (*proto.CreateApprovalResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for CreateApproval")
	}

	var r0 *proto.CreateApprovalResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *proto.CreateApprovalRequest) (*proto.CreateApprovalResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *proto.CreateApprovalRequest) *proto.CreateApprovalResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*proto.CreateApprovalResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *proto.CreateApprovalRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Mockapproval_service_server_CreateApproval_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateApproval'
type Mockapproval_service_server_CreateApproval_Call struct {
	*mock.Call
}

// CreateApproval is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *proto.CreateApprovalRequest
func (_e *Mockapproval_service_server_Expecter) CreateApproval(_a0 interface{}, _a1 interface{}) *Mockapproval_service_server_CreateApproval_Call {
	return &Mockapproval_service_server_CreateApproval_Call{Call: _e.mock.On("CreateApproval", _a0, _a1)}
}

func (_c *Mockapproval_service_server_CreateApproval_Call) Run(run func(_a0 context.Context, _a1 *proto.CreateApprovalRequest)) *Mockapproval_service_server_CreateApproval_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*proto.CreateApprovalRequest))
	})
	return _c
}

func (_c *Mockapproval_service_server_CreateApproval_Call) Return(_a0 *proto.CreateApprovalResponse, _a1 error) *Mockapproval_service_server_CreateApproval_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Mockapproval_service_server_CreateApproval_Call) RunAndReturn(run func(context.Context, *proto.CreateApprovalRequest) (*proto.CreateApprovalResponse, error)) *Mockapproval_service_server_CreateApproval_Call {
	_c.Call.Return(run)
	return _c
}

// CreateFunction provides a mock function with given fields: _a0, _a1
func (_m *Mockapproval_service_server) CreateFunction(_a0 context.Context, _a1 *proto.CreateFunctionRequest) (*proto.CreateFunctionResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for CreateFunction")
	}

	var r0 *proto.CreateFunctionResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *proto.CreateFunctionRequest) (*proto.CreateFunctionResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *proto.CreateFunctionRequest) *proto.CreateFunctionResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*proto.CreateFunctionResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *proto.CreateFunctionRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Mockapproval_service_server_CreateFunction_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateFunction'
type Mockapproval_service_server_CreateFunction_Call struct {
	*mock.Call
}

// CreateFunction is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *proto.CreateFunctionRequest
func (_e *Mockapproval_service_server_Expecter) CreateFunction(_a0 interface{}, _a1 interface{}) *Mockapproval_service_server_CreateFunction_Call {
	return &Mockapproval_service_server_CreateFunction_Call{Call: _e.mock.On("CreateFunction", _a0, _a1)}
}

func (_c *Mockapproval_service_server_CreateFunction_Call) Run(run func(_a0 context.Context, _a1 *proto.CreateFunctionRequest)) *Mockapproval_service_server_CreateFunction_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*proto.CreateFunctionRequest))
	})
	return _c
}

func (_c *Mockapproval_service_server_CreateFunction_Call) Return(_a0 *proto.CreateFunctionResponse, _a1 error) *Mockapproval_service_server_CreateFunction_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Mockapproval_service_server_CreateFunction_Call) RunAndReturn(run func(context.Context, *proto.CreateFunctionRequest) (*proto.CreateFunctionResponse, error)) *Mockapproval_service_server_CreateFunction_Call {
	_c.Call.Return(run)
	return _c
}

// CreateRole provides a mock function with given fields: _a0, _a1
func (_m *Mockapproval_service_server) CreateRole(_a0 context.Context, _a1 *proto.CreateRoleRequest) (*proto.CreateRoleResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for CreateRole")
	}

	var r0 *proto.CreateRoleResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *proto.CreateRoleRequest) (*proto.CreateRoleResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *proto.CreateRoleRequest) *proto.CreateRoleResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*proto.CreateRoleResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *proto.CreateRoleRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Mockapproval_service_server_CreateRole_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateRole'
type Mockapproval_service_server_CreateRole_Call struct {
	*mock.Call
}

// CreateRole is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *proto.CreateRoleRequest
func (_e *Mockapproval_service_server_Expecter) CreateRole(_a0 interface{}, _a1 interface{}) *Mockapproval_service_server_CreateRole_Call {
	return &Mockapproval_service_server_CreateRole_Call{Call: _e.mock.On("CreateRole", _a0, _a1)}
}

func (_c *Mockapproval_service_server_CreateRole_Call) Run(run func(_a0 context.Context, _a1 *proto.CreateRoleRequest)) *Mockapproval_service_server_CreateRole_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*proto.CreateRoleRequest))
	})
	return _c
}

func (_c *Mockapproval_service_server_CreateRole_Call) Return(_a0 *proto.CreateRoleResponse, _a1 error) *Mockapproval_service_server_CreateRole_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Mockapproval_service_server_CreateRole_Call) RunAndReturn(run func(context.Context, *proto.CreateRoleRequest) (*proto.CreateRoleResponse, error)) *Mockapproval_service_server_CreateRole_Call {
	_c.Call.Return(run)
	return _c
}

// CreateRoleAssignment provides a mock function with given fields: _a0, _a1
func (_m *Mockapproval_service_server) CreateRoleAssignment(_a0 context.Context, _a1 *proto.CreateRoleAssignmentRequest) (*proto.CreateRoleAssignmentResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for CreateRoleAssignment")
	}

	var r0 *proto.CreateRoleAssignmentResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *proto.CreateRoleAssignmentRequest) (*proto.CreateRoleAssignmentResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *proto.CreateRoleAssignmentRequest) *proto.CreateRoleAssignmentResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*proto.CreateRoleAssignmentResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *proto.CreateRoleAssignmentRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Mockapproval_service_server_CreateRoleAssignment_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateRoleAssignment'
type Mockapproval_service_server_CreateRoleAssignment_Call struct {
	*mock.Call
}

// CreateRoleAssignment is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *proto.CreateRoleAssignmentRequest
func (_e *Mockapproval_service_server_Expecter) CreateRoleAssignment(_a0 interface{}, _a1 interface{}) *Mockapproval_service_server_CreateRoleAssignment_Call {
	return &Mockapproval_service_server_CreateRoleAssignment_Call{Call: _e.mock.On("CreateRoleAssignment", _a0, _a1)}
}

func (_c *Mockapproval_service_server_CreateRoleAssignment_Call) Run(run func(_a0 context.Context, _a1 *proto.CreateRoleAssignmentRequest)) *Mockapproval_service_server_CreateRoleAssignment_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*proto.CreateRoleAssignmentRequest))
	})
	return _c
}

func (_c *Mockapproval_service_server_CreateRoleAssignment_Call) Return(_a0 *proto.CreateRoleAssignmentResponse, _a1 error) *Mockapproval_service_server_CreateRoleAssignment_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Mockapproval_service_server_CreateRoleAssignment_Call) RunAndReturn(run func(context.Context, *proto.CreateRoleAssignmentRequest) (*proto.CreateRoleAssignmentResponse, error)) *Mockapproval_service_server_CreateRoleAssignment_Call {
	_c.Call.Return(run)
	return _c
}

// CreateUser provides a mock function with given fields: _a0, _a1
func (_m *Mockapproval_service_server) CreateUser(_a0 context.Context, _a1 *proto.CreateUserRequest) (*proto.CreateUserResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for CreateUser")
	}

	var r0 *proto.CreateUserResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *proto.CreateUserRequest) (*proto.CreateUserResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *proto.CreateUserRequest) *proto.CreateUserResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*proto.CreateUserResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *proto.CreateUserRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Mockapproval_service_server_CreateUser_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateUser'
type Mockapproval_service_server_CreateUser_Call struct {
	*mock.Call
}

// CreateUser is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *proto.CreateUserRequest
func (_e *Mockapproval_service_server_Expecter) CreateUser(_a0 interface{}, _a1 interface{}) *Mockapproval_service_server_CreateUser_Call {
	return &Mockapproval_service_server_CreateUser_Call{Call: _e.mock.On("CreateUser", _a0, _a1)}
}

func (_c *Mockapproval_service_server_CreateUser_Call) Run(run func(_a0 context.Context, _a1 *proto.CreateUserRequest)) *Mockapproval_service_server_CreateUser_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*proto.CreateUserRequest))
	})
	return _c
}

func (_c *Mockapproval_service_server_CreateUser_Call) Return(_a0 *proto.CreateUserResponse, _a1 error) *Mockapproval_service_server_CreateUser_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Mockapproval_service_server_CreateUser_Call) RunAndReturn(run func(context.Context, *proto.CreateUserRequest) (*proto.CreateUserResponse, error)) *Mockapproval_service_server_CreateUser_Call {
	_c.Call.Return(run)
	return _c
}

// GetFunctions provides a mock function with given fields: _a0, _a1
func (_m *Mockapproval_service_server) GetFunctions(_a0 context.Context, _a1 *proto.GetFunctionRequest) (*proto.GetFunctionResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for GetFunctions")
	}

	var r0 *proto.GetFunctionResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *proto.GetFunctionRequest) (*proto.GetFunctionResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *proto.GetFunctionRequest) *proto.GetFunctionResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*proto.GetFunctionResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *proto.GetFunctionRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Mockapproval_service_server_GetFunctions_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetFunctions'
type Mockapproval_service_server_GetFunctions_Call struct {
	*mock.Call
}

// GetFunctions is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *proto.GetFunctionRequest
func (_e *Mockapproval_service_server_Expecter) GetFunctions(_a0 interface{}, _a1 interface{}) *Mockapproval_service_server_GetFunctions_Call {
	return &Mockapproval_service_server_GetFunctions_Call{Call: _e.mock.On("GetFunctions", _a0, _a1)}
}

func (_c *Mockapproval_service_server_GetFunctions_Call) Run(run func(_a0 context.Context, _a1 *proto.GetFunctionRequest)) *Mockapproval_service_server_GetFunctions_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*proto.GetFunctionRequest))
	})
	return _c
}

func (_c *Mockapproval_service_server_GetFunctions_Call) Return(_a0 *proto.GetFunctionResponse, _a1 error) *Mockapproval_service_server_GetFunctions_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Mockapproval_service_server_GetFunctions_Call) RunAndReturn(run func(context.Context, *proto.GetFunctionRequest) (*proto.GetFunctionResponse, error)) *Mockapproval_service_server_GetFunctions_Call {
	_c.Call.Return(run)
	return _c
}

// GetRoleAssignments provides a mock function with given fields: _a0, _a1
func (_m *Mockapproval_service_server) GetRoleAssignments(_a0 context.Context, _a1 *proto.GetRoleAssignmentRequest) (*proto.GetRoleAssignmentResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for GetRoleAssignments")
	}

	var r0 *proto.GetRoleAssignmentResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *proto.GetRoleAssignmentRequest) (*proto.GetRoleAssignmentResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *proto.GetRoleAssignmentRequest) *proto.GetRoleAssignmentResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*proto.GetRoleAssignmentResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *proto.GetRoleAssignmentRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Mockapproval_service_server_GetRoleAssignments_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetRoleAssignments'
type Mockapproval_service_server_GetRoleAssignments_Call struct {
	*mock.Call
}

// GetRoleAssignments is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *proto.GetRoleAssignmentRequest
func (_e *Mockapproval_service_server_Expecter) GetRoleAssignments(_a0 interface{}, _a1 interface{}) *Mockapproval_service_server_GetRoleAssignments_Call {
	return &Mockapproval_service_server_GetRoleAssignments_Call{Call: _e.mock.On("GetRoleAssignments", _a0, _a1)}
}

func (_c *Mockapproval_service_server_GetRoleAssignments_Call) Run(run func(_a0 context.Context, _a1 *proto.GetRoleAssignmentRequest)) *Mockapproval_service_server_GetRoleAssignments_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*proto.GetRoleAssignmentRequest))
	})
	return _c
}

func (_c *Mockapproval_service_server_GetRoleAssignments_Call) Return(_a0 *proto.GetRoleAssignmentResponse, _a1 error) *Mockapproval_service_server_GetRoleAssignments_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Mockapproval_service_server_GetRoleAssignments_Call) RunAndReturn(run func(context.Context, *proto.GetRoleAssignmentRequest) (*proto.GetRoleAssignmentResponse, error)) *Mockapproval_service_server_GetRoleAssignments_Call {
	_c.Call.Return(run)
	return _c
}

// GetRoles provides a mock function with given fields: _a0, _a1
func (_m *Mockapproval_service_server) GetRoles(_a0 context.Context, _a1 *proto.GetRoleRequest) (*proto.GetRoleResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for GetRoles")
	}

	var r0 *proto.GetRoleResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *proto.GetRoleRequest) (*proto.GetRoleResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *proto.GetRoleRequest) *proto.GetRoleResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*proto.GetRoleResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *proto.GetRoleRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Mockapproval_service_server_GetRoles_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetRoles'
type Mockapproval_service_server_GetRoles_Call struct {
	*mock.Call
}

// GetRoles is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *proto.GetRoleRequest
func (_e *Mockapproval_service_server_Expecter) GetRoles(_a0 interface{}, _a1 interface{}) *Mockapproval_service_server_GetRoles_Call {
	return &Mockapproval_service_server_GetRoles_Call{Call: _e.mock.On("GetRoles", _a0, _a1)}
}

func (_c *Mockapproval_service_server_GetRoles_Call) Run(run func(_a0 context.Context, _a1 *proto.GetRoleRequest)) *Mockapproval_service_server_GetRoles_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*proto.GetRoleRequest))
	})
	return _c
}

func (_c *Mockapproval_service_server_GetRoles_Call) Return(_a0 *proto.GetRoleResponse, _a1 error) *Mockapproval_service_server_GetRoles_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Mockapproval_service_server_GetRoles_Call) RunAndReturn(run func(context.Context, *proto.GetRoleRequest) (*proto.GetRoleResponse, error)) *Mockapproval_service_server_GetRoles_Call {
	_c.Call.Return(run)
	return _c
}

// GetUser provides a mock function with given fields: _a0, _a1
func (_m *Mockapproval_service_server) GetUser(_a0 context.Context, _a1 *proto.GetUserRequest) (*proto.GetUserResponse, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for GetUser")
	}

	var r0 *proto.GetUserResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *proto.GetUserRequest) (*proto.GetUserResponse, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *proto.GetUserRequest) *proto.GetUserResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*proto.GetUserResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *proto.GetUserRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Mockapproval_service_server_GetUser_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetUser'
type Mockapproval_service_server_GetUser_Call struct {
	*mock.Call
}

// GetUser is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *proto.GetUserRequest
func (_e *Mockapproval_service_server_Expecter) GetUser(_a0 interface{}, _a1 interface{}) *Mockapproval_service_server_GetUser_Call {
	return &Mockapproval_service_server_GetUser_Call{Call: _e.mock.On("GetUser", _a0, _a1)}
}

func (_c *Mockapproval_service_server_GetUser_Call) Run(run func(_a0 context.Context, _a1 *proto.GetUserRequest)) *Mockapproval_service_server_GetUser_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*proto.GetUserRequest))
	})
	return _c
}

func (_c *Mockapproval_service_server_GetUser_Call) Return(_a0 *proto.GetUserResponse, _a1 error) *Mockapproval_service_server_GetUser_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Mockapproval_service_server_GetUser_Call) RunAndReturn(run func(context.Context, *proto.GetUserRequest) (*proto.GetUserResponse, error)) *Mockapproval_service_server_GetUser_Call {
	_c.Call.Return(run)
	return _c
}

// mustEmbedUnimplementedApprovalServiceServer provides a mock function with given fields:
func (_m *Mockapproval_service_server) mustEmbedUnimplementedApprovalServiceServer() {
	_m.Called()
}

// Mockapproval_service_server_mustEmbedUnimplementedApprovalServiceServer_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'mustEmbedUnimplementedApprovalServiceServer'
type Mockapproval_service_server_mustEmbedUnimplementedApprovalServiceServer_Call struct {
	*mock.Call
}

// mustEmbedUnimplementedApprovalServiceServer is a helper method to define mock.On call
func (_e *Mockapproval_service_server_Expecter) mustEmbedUnimplementedApprovalServiceServer() *Mockapproval_service_server_mustEmbedUnimplementedApprovalServiceServer_Call {
	return &Mockapproval_service_server_mustEmbedUnimplementedApprovalServiceServer_Call{Call: _e.mock.On("mustEmbedUnimplementedApprovalServiceServer")}
}

func (_c *Mockapproval_service_server_mustEmbedUnimplementedApprovalServiceServer_Call) Run(run func()) *Mockapproval_service_server_mustEmbedUnimplementedApprovalServiceServer_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Mockapproval_service_server_mustEmbedUnimplementedApprovalServiceServer_Call) Return() *Mockapproval_service_server_mustEmbedUnimplementedApprovalServiceServer_Call {
	_c.Call.Return()
	return _c
}

func (_c *Mockapproval_service_server_mustEmbedUnimplementedApprovalServiceServer_Call) RunAndReturn(run func()) *Mockapproval_service_server_mustEmbedUnimplementedApprovalServiceServer_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockapproval_service_server creates a new instance of Mockapproval_service_server. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockapproval_service_server(t interface {
	mock.TestingT
	Cleanup(func())
}) *Mockapproval_service_server {
	mock := &Mockapproval_service_server{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}