# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: dgt_settings/protobuf/processor.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from dgt_settings.protobuf import transaction_pb2 as dgt__settings_dot_protobuf_dot_transaction__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='dgt_settings/protobuf/processor.proto',
  package='',
  syntax='proto3',
  serialized_options=_b('\n\025sawtooth.sdk.protobufP\001Z\rprocessor_pb2'),
  serialized_pb=_b('\n%dgt_settings/protobuf/processor.proto\x1a\'dgt_settings/protobuf/transaction.proto\"_\n\x11TpRegisterRequest\x12\x0e\n\x06\x66\x61mily\x18\x01 \x01(\t\x12\x0f\n\x07version\x18\x02 \x01(\t\x12\x12\n\nnamespaces\x18\x04 \x03(\t\x12\x15\n\rmax_occupancy\x18\x05 \x01(\r\"o\n\x12TpRegisterResponse\x12*\n\x06status\x18\x01 \x01(\x0e\x32\x1a.TpRegisterResponse.Status\"-\n\x06Status\x12\x10\n\x0cSTATUS_UNSET\x10\x00\x12\x06\n\x02OK\x10\x01\x12\t\n\x05\x45RROR\x10\x02\"\x15\n\x13TpUnregisterRequest\"s\n\x14TpUnregisterResponse\x12,\n\x06status\x18\x01 \x01(\x0e\x32\x1c.TpUnregisterResponse.Status\"-\n\x06Status\x12\x10\n\x0cSTATUS_UNSET\x10\x00\x12\x06\n\x02OK\x10\x01\x12\t\n\x05\x45RROR\x10\x02\"n\n\x10TpProcessRequest\x12\"\n\x06header\x18\x01 \x01(\x0b\x32\x12.TransactionHeader\x12\x0f\n\x07payload\x18\x02 \x01(\x0c\x12\x11\n\tsignature\x18\x03 \x01(\t\x12\x12\n\ncontext_id\x18\x04 \x01(\t\"\xb7\x01\n\x11TpProcessResponse\x12)\n\x06status\x18\x01 \x01(\x0e\x32\x19.TpProcessResponse.Status\x12\x0f\n\x07message\x18\x02 \x01(\t\x12\x15\n\rextended_data\x18\x03 \x01(\x0c\"O\n\x06Status\x12\x10\n\x0cSTATUS_UNSET\x10\x00\x12\x06\n\x02OK\x10\x01\x12\x17\n\x13INVALID_TRANSACTION\x10\x02\x12\x12\n\x0eINTERNAL_ERROR\x10\x03\x42(\n\x15sawtooth.sdk.protobufP\x01Z\rprocessor_pb2b\x06proto3')
  ,
  dependencies=[dgt__settings_dot_protobuf_dot_transaction__pb2.DESCRIPTOR,])



_TPREGISTERRESPONSE_STATUS = _descriptor.EnumDescriptor(
  name='Status',
  full_name='TpRegisterResponse.Status',
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
  serialized_start=245,
  serialized_end=290,
)
_sym_db.RegisterEnumDescriptor(_TPREGISTERRESPONSE_STATUS)

_TPUNREGISTERRESPONSE_STATUS = _descriptor.EnumDescriptor(
  name='Status',
  full_name='TpUnregisterResponse.Status',
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
  serialized_start=245,
  serialized_end=290,
)
_sym_db.RegisterEnumDescriptor(_TPUNREGISTERRESPONSE_STATUS)

_TPPROCESSRESPONSE_STATUS = _descriptor.EnumDescriptor(
  name='Status',
  full_name='TpProcessResponse.Status',
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
      name='INVALID_TRANSACTION', index=2, number=2,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='INTERNAL_ERROR', index=3, number=3,
      serialized_options=None,
      type=None),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=649,
  serialized_end=728,
)
_sym_db.RegisterEnumDescriptor(_TPPROCESSRESPONSE_STATUS)


_TPREGISTERREQUEST = _descriptor.Descriptor(
  name='TpRegisterRequest',
  full_name='TpRegisterRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='family', full_name='TpRegisterRequest.family', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='version', full_name='TpRegisterRequest.version', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='namespaces', full_name='TpRegisterRequest.namespaces', index=2,
      number=4, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='max_occupancy', full_name='TpRegisterRequest.max_occupancy', index=3,
      number=5, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
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
  serialized_start=82,
  serialized_end=177,
)


_TPREGISTERRESPONSE = _descriptor.Descriptor(
  name='TpRegisterResponse',
  full_name='TpRegisterResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='status', full_name='TpRegisterResponse.status', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _TPREGISTERRESPONSE_STATUS,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=179,
  serialized_end=290,
)


_TPUNREGISTERREQUEST = _descriptor.Descriptor(
  name='TpUnregisterRequest',
  full_name='TpUnregisterRequest',
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
  serialized_start=292,
  serialized_end=313,
)


_TPUNREGISTERRESPONSE = _descriptor.Descriptor(
  name='TpUnregisterResponse',
  full_name='TpUnregisterResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='status', full_name='TpUnregisterResponse.status', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _TPUNREGISTERRESPONSE_STATUS,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=315,
  serialized_end=430,
)


_TPPROCESSREQUEST = _descriptor.Descriptor(
  name='TpProcessRequest',
  full_name='TpProcessRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='header', full_name='TpProcessRequest.header', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='payload', full_name='TpProcessRequest.payload', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='signature', full_name='TpProcessRequest.signature', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='context_id', full_name='TpProcessRequest.context_id', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
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
  serialized_start=432,
  serialized_end=542,
)


_TPPROCESSRESPONSE = _descriptor.Descriptor(
  name='TpProcessResponse',
  full_name='TpProcessResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='status', full_name='TpProcessResponse.status', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='message', full_name='TpProcessResponse.message', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='extended_data', full_name='TpProcessResponse.extended_data', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _TPPROCESSRESPONSE_STATUS,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=545,
  serialized_end=728,
)

_TPREGISTERRESPONSE.fields_by_name['status'].enum_type = _TPREGISTERRESPONSE_STATUS
_TPREGISTERRESPONSE_STATUS.containing_type = _TPREGISTERRESPONSE
_TPUNREGISTERRESPONSE.fields_by_name['status'].enum_type = _TPUNREGISTERRESPONSE_STATUS
_TPUNREGISTERRESPONSE_STATUS.containing_type = _TPUNREGISTERRESPONSE
_TPPROCESSREQUEST.fields_by_name['header'].message_type = dgt__settings_dot_protobuf_dot_transaction__pb2._TRANSACTIONHEADER
_TPPROCESSRESPONSE.fields_by_name['status'].enum_type = _TPPROCESSRESPONSE_STATUS
_TPPROCESSRESPONSE_STATUS.containing_type = _TPPROCESSRESPONSE
DESCRIPTOR.message_types_by_name['TpRegisterRequest'] = _TPREGISTERREQUEST
DESCRIPTOR.message_types_by_name['TpRegisterResponse'] = _TPREGISTERRESPONSE
DESCRIPTOR.message_types_by_name['TpUnregisterRequest'] = _TPUNREGISTERREQUEST
DESCRIPTOR.message_types_by_name['TpUnregisterResponse'] = _TPUNREGISTERRESPONSE
DESCRIPTOR.message_types_by_name['TpProcessRequest'] = _TPPROCESSREQUEST
DESCRIPTOR.message_types_by_name['TpProcessResponse'] = _TPPROCESSRESPONSE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

TpRegisterRequest = _reflection.GeneratedProtocolMessageType('TpRegisterRequest', (_message.Message,), dict(
  DESCRIPTOR = _TPREGISTERREQUEST,
  __module__ = 'dgt_settings.protobuf.processor_pb2'
  # @@protoc_insertion_point(class_scope:TpRegisterRequest)
  ))
_sym_db.RegisterMessage(TpRegisterRequest)

TpRegisterResponse = _reflection.GeneratedProtocolMessageType('TpRegisterResponse', (_message.Message,), dict(
  DESCRIPTOR = _TPREGISTERRESPONSE,
  __module__ = 'dgt_settings.protobuf.processor_pb2'
  # @@protoc_insertion_point(class_scope:TpRegisterResponse)
  ))
_sym_db.RegisterMessage(TpRegisterResponse)

TpUnregisterRequest = _reflection.GeneratedProtocolMessageType('TpUnregisterRequest', (_message.Message,), dict(
  DESCRIPTOR = _TPUNREGISTERREQUEST,
  __module__ = 'dgt_settings.protobuf.processor_pb2'
  # @@protoc_insertion_point(class_scope:TpUnregisterRequest)
  ))
_sym_db.RegisterMessage(TpUnregisterRequest)

TpUnregisterResponse = _reflection.GeneratedProtocolMessageType('TpUnregisterResponse', (_message.Message,), dict(
  DESCRIPTOR = _TPUNREGISTERRESPONSE,
  __module__ = 'dgt_settings.protobuf.processor_pb2'
  # @@protoc_insertion_point(class_scope:TpUnregisterResponse)
  ))
_sym_db.RegisterMessage(TpUnregisterResponse)

TpProcessRequest = _reflection.GeneratedProtocolMessageType('TpProcessRequest', (_message.Message,), dict(
  DESCRIPTOR = _TPPROCESSREQUEST,
  __module__ = 'dgt_settings.protobuf.processor_pb2'
  # @@protoc_insertion_point(class_scope:TpProcessRequest)
  ))
_sym_db.RegisterMessage(TpProcessRequest)

TpProcessResponse = _reflection.GeneratedProtocolMessageType('TpProcessResponse', (_message.Message,), dict(
  DESCRIPTOR = _TPPROCESSRESPONSE,
  __module__ = 'dgt_settings.protobuf.processor_pb2'
  # @@protoc_insertion_point(class_scope:TpProcessResponse)
  ))
_sym_db.RegisterMessage(TpProcessResponse)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
