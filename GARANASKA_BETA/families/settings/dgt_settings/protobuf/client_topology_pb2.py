# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: dgt_settings/protobuf/client_topology.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='dgt_settings/protobuf/client_topology.proto',
  package='',
  syntax='proto3',
  serialized_options=_b('\n\025sawtooth.sdk.protobufP\001Z\017client_topology'),
  serialized_pb=_b('\n+dgt_settings/protobuf/client_topology.proto\"\x1a\n\x18\x43lientTopologyGetRequest\"\x8f\x01\n\x19\x43lientTopologyGetResponse\x12\x31\n\x06status\x18\x01 \x01(\x0e\x32!.ClientTopologyGetResponse.Status\x12\x10\n\x08topology\x18\x02 \x01(\x0c\"-\n\x06Status\x12\x10\n\x0cSTATUS_UNSET\x10\x00\x12\x06\n\x02OK\x10\x01\x12\t\n\x05\x45RROR\x10\x02\"\x16\n\x14\x43lientGateGetRequest\"\x84\x01\n\x15\x43lientGateGetResponse\x12-\n\x06status\x18\x01 \x01(\x0e\x32\x1d.ClientGateGetResponse.Status\x12\r\n\x05gates\x18\x02 \x01(\x0c\"-\n\x06Status\x12\x10\n\x0cSTATUS_UNSET\x10\x00\x12\x06\n\x02OK\x10\x01\x12\t\n\x05\x45RROR\x10\x02\x42*\n\x15sawtooth.sdk.protobufP\x01Z\x0f\x63lient_topologyb\x06proto3')
)



_CLIENTTOPOLOGYGETRESPONSE_STATUS = _descriptor.EnumDescriptor(
  name='Status',
  full_name='ClientTopologyGetResponse.Status',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='STATUS_UNSET', index=0, number=0,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='OK', index=1, number=1,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ERROR', index=2, number=2,
      serialized_options=None,
      type=None),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=174,
  serialized_end=219,
)
_sym_db.RegisterEnumDescriptor(_CLIENTTOPOLOGYGETRESPONSE_STATUS)

_CLIENTGATEGETRESPONSE_STATUS = _descriptor.EnumDescriptor(
  name='Status',
  full_name='ClientGateGetResponse.Status',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='STATUS_UNSET', index=0, number=0,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='OK', index=1, number=1,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ERROR', index=2, number=2,
      serialized_options=None,
      type=None),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=174,
  serialized_end=219,
)
_sym_db.RegisterEnumDescriptor(_CLIENTGATEGETRESPONSE_STATUS)


_CLIENTTOPOLOGYGETREQUEST = _descriptor.Descriptor(
  name='ClientTopologyGetRequest',
  full_name='ClientTopologyGetRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=47,
  serialized_end=73,
)


_CLIENTTOPOLOGYGETRESPONSE = _descriptor.Descriptor(
  name='ClientTopologyGetResponse',
  full_name='ClientTopologyGetResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='status', full_name='ClientTopologyGetResponse.status', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='topology', full_name='ClientTopologyGetResponse.topology', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _CLIENTTOPOLOGYGETRESPONSE_STATUS,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=76,
  serialized_end=219,
)


_CLIENTGATEGETREQUEST = _descriptor.Descriptor(
  name='ClientGateGetRequest',
  full_name='ClientGateGetRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=221,
  serialized_end=243,
)


_CLIENTGATEGETRESPONSE = _descriptor.Descriptor(
  name='ClientGateGetResponse',
  full_name='ClientGateGetResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='status', full_name='ClientGateGetResponse.status', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='gates', full_name='ClientGateGetResponse.gates', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _CLIENTGATEGETRESPONSE_STATUS,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=246,
  serialized_end=378,
)

_CLIENTTOPOLOGYGETRESPONSE.fields_by_name['status'].enum_type = _CLIENTTOPOLOGYGETRESPONSE_STATUS
_CLIENTTOPOLOGYGETRESPONSE_STATUS.containing_type = _CLIENTTOPOLOGYGETRESPONSE
_CLIENTGATEGETRESPONSE.fields_by_name['status'].enum_type = _CLIENTGATEGETRESPONSE_STATUS
_CLIENTGATEGETRESPONSE_STATUS.containing_type = _CLIENTGATEGETRESPONSE
DESCRIPTOR.message_types_by_name['ClientTopologyGetRequest'] = _CLIENTTOPOLOGYGETREQUEST
DESCRIPTOR.message_types_by_name['ClientTopologyGetResponse'] = _CLIENTTOPOLOGYGETRESPONSE
DESCRIPTOR.message_types_by_name['ClientGateGetRequest'] = _CLIENTGATEGETREQUEST
DESCRIPTOR.message_types_by_name['ClientGateGetResponse'] = _CLIENTGATEGETRESPONSE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ClientTopologyGetRequest = _reflection.GeneratedProtocolMessageType('ClientTopologyGetRequest', (_message.Message,), dict(
  DESCRIPTOR = _CLIENTTOPOLOGYGETREQUEST,
  __module__ = 'dgt_settings.protobuf.client_topology_pb2'
  # @@protoc_insertion_point(class_scope:ClientTopologyGetRequest)
  ))
_sym_db.RegisterMessage(ClientTopologyGetRequest)

ClientTopologyGetResponse = _reflection.GeneratedProtocolMessageType('ClientTopologyGetResponse', (_message.Message,), dict(
  DESCRIPTOR = _CLIENTTOPOLOGYGETRESPONSE,
  __module__ = 'dgt_settings.protobuf.client_topology_pb2'
  # @@protoc_insertion_point(class_scope:ClientTopologyGetResponse)
  ))
_sym_db.RegisterMessage(ClientTopologyGetResponse)

ClientGateGetRequest = _reflection.GeneratedProtocolMessageType('ClientGateGetRequest', (_message.Message,), dict(
  DESCRIPTOR = _CLIENTGATEGETREQUEST,
  __module__ = 'dgt_settings.protobuf.client_topology_pb2'
  # @@protoc_insertion_point(class_scope:ClientGateGetRequest)
  ))
_sym_db.RegisterMessage(ClientGateGetRequest)

ClientGateGetResponse = _reflection.GeneratedProtocolMessageType('ClientGateGetResponse', (_message.Message,), dict(
  DESCRIPTOR = _CLIENTGATEGETRESPONSE,
  __module__ = 'dgt_settings.protobuf.client_topology_pb2'
  # @@protoc_insertion_point(class_scope:ClientGateGetResponse)
  ))
_sym_db.RegisterMessage(ClientGateGetResponse)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
