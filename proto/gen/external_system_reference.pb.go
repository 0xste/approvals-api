// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.25.1
// source: models/external_system_reference.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	anypb "google.golang.org/protobuf/types/known/anypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type IdentityProvider int32

const (
	IdentityProvider_IDP_GCP  IdentityProvider = 0
	IdentityProvider_IDP_OKTA IdentityProvider = 1
)

// Enum value maps for IdentityProvider.
var (
	IdentityProvider_name = map[int32]string{
		0: "IDP_GCP",
		1: "IDP_OKTA",
	}
	IdentityProvider_value = map[string]int32{
		"IDP_GCP":  0,
		"IDP_OKTA": 1,
	}
)

func (x IdentityProvider) Enum() *IdentityProvider {
	p := new(IdentityProvider)
	*p = x
	return p
}

func (x IdentityProvider) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (IdentityProvider) Descriptor() protoreflect.EnumDescriptor {
	return file_models_external_system_reference_proto_enumTypes[0].Descriptor()
}

func (IdentityProvider) Type() protoreflect.EnumType {
	return &file_models_external_system_reference_proto_enumTypes[0]
}

func (x IdentityProvider) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use IdentityProvider.Descriptor instead.
func (IdentityProvider) EnumDescriptor() ([]byte, []int) {
	return file_models_external_system_reference_proto_rawDescGZIP(), []int{0}
}

type IdentityProviderReference struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IdentityProvider IdentityProvider `protobuf:"varint,1,opt,name=identityProvider,json=provider,proto3,enum=proto.IdentityProvider" json:"identityProvider,omitempty"`
	ExternalId       string           `protobuf:"bytes,10,opt,name=externalId,json=external_id,proto3" json:"externalId,omitempty"`
	Metadata         *anypb.Any       `protobuf:"bytes,20,opt,name=metadata,proto3" json:"metadata,omitempty"`
}

func (x *IdentityProviderReference) Reset() {
	*x = IdentityProviderReference{}
	if protoimpl.UnsafeEnabled {
		mi := &file_models_external_system_reference_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IdentityProviderReference) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IdentityProviderReference) ProtoMessage() {}

func (x *IdentityProviderReference) ProtoReflect() protoreflect.Message {
	mi := &file_models_external_system_reference_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IdentityProviderReference.ProtoReflect.Descriptor instead.
func (*IdentityProviderReference) Descriptor() ([]byte, []int) {
	return file_models_external_system_reference_proto_rawDescGZIP(), []int{0}
}

func (x *IdentityProviderReference) GetIdentityProvider() IdentityProvider {
	if x != nil {
		return x.IdentityProvider
	}
	return IdentityProvider_IDP_GCP
}

func (x *IdentityProviderReference) GetExternalId() string {
	if x != nil {
		return x.ExternalId
	}
	return ""
}

func (x *IdentityProviderReference) GetMetadata() *anypb.Any {
	if x != nil {
		return x.Metadata
	}
	return nil
}

var File_models_external_system_reference_proto protoreflect.FileDescriptor

var file_models_external_system_reference_proto_rawDesc = []byte{
	0x0a, 0x26, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x73, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61,
	0x6c, 0x5f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x5f, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e,
	0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xab, 0x01, 0x0a, 0x19, 0x49,
	0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x52,
	0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x12, 0x3b, 0x0a, 0x10, 0x69, 0x64, 0x65, 0x6e,
	0x74, 0x69, 0x74, 0x79, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0e, 0x32, 0x17, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x49, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x74, 0x79, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x52, 0x08, 0x70, 0x72, 0x6f,
	0x76, 0x69, 0x64, 0x65, 0x72, 0x12, 0x1f, 0x0a, 0x0a, 0x65, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61,
	0x6c, 0x49, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x65, 0x78, 0x74, 0x65, 0x72,
	0x6e, 0x61, 0x6c, 0x5f, 0x69, 0x64, 0x12, 0x30, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0x18, 0x14, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x41, 0x6e, 0x79, 0x52, 0x08,
	0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2a, 0x2d, 0x0a, 0x10, 0x49, 0x64, 0x65, 0x6e,
	0x74, 0x69, 0x74, 0x79, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x12, 0x0b, 0x0a, 0x07,
	0x49, 0x44, 0x50, 0x5f, 0x47, 0x43, 0x50, 0x10, 0x00, 0x12, 0x0c, 0x0a, 0x08, 0x49, 0x44, 0x50,
	0x5f, 0x4f, 0x4b, 0x54, 0x41, 0x10, 0x01, 0x42, 0x09, 0x5a, 0x07, 0x2e, 0x3b, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_models_external_system_reference_proto_rawDescOnce sync.Once
	file_models_external_system_reference_proto_rawDescData = file_models_external_system_reference_proto_rawDesc
)

func file_models_external_system_reference_proto_rawDescGZIP() []byte {
	file_models_external_system_reference_proto_rawDescOnce.Do(func() {
		file_models_external_system_reference_proto_rawDescData = protoimpl.X.CompressGZIP(file_models_external_system_reference_proto_rawDescData)
	})
	return file_models_external_system_reference_proto_rawDescData
}

var file_models_external_system_reference_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_models_external_system_reference_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_models_external_system_reference_proto_goTypes = []interface{}{
	(IdentityProvider)(0),             // 0: proto.IdentityProvider
	(*IdentityProviderReference)(nil), // 1: proto.IdentityProviderReference
	(*anypb.Any)(nil),                 // 2: google.protobuf.Any
}
var file_models_external_system_reference_proto_depIdxs = []int32{
	0, // 0: proto.IdentityProviderReference.identityProvider:type_name -> proto.IdentityProvider
	2, // 1: proto.IdentityProviderReference.metadata:type_name -> google.protobuf.Any
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_models_external_system_reference_proto_init() }
func file_models_external_system_reference_proto_init() {
	if File_models_external_system_reference_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_models_external_system_reference_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IdentityProviderReference); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_models_external_system_reference_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_models_external_system_reference_proto_goTypes,
		DependencyIndexes: file_models_external_system_reference_proto_depIdxs,
		EnumInfos:         file_models_external_system_reference_proto_enumTypes,
		MessageInfos:      file_models_external_system_reference_proto_msgTypes,
	}.Build()
	File_models_external_system_reference_proto = out.File
	file_models_external_system_reference_proto_rawDesc = nil
	file_models_external_system_reference_proto_goTypes = nil
	file_models_external_system_reference_proto_depIdxs = nil
}
