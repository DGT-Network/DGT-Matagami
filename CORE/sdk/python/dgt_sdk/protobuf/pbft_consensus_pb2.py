# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: dgt_sdk/protobuf/pbft_consensus.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from dgt_sdk.protobuf import consensus_pb2 as dgt__sdk_dot_protobuf_dot_consensus__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='dgt_sdk/protobuf/pbft_consensus.proto',
  package='',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=_b('\n%dgt_sdk/protobuf/pbft_consensus.proto\x1a dgt_sdk/protobuf/consensus.proto\"[\n\x10PbftBlockMessage\x12\x10\n\x08\x62lock_id\x18\x01 \x01(\x0c\x12\x11\n\tsigner_id\x18\x03 \x01(\x0c\x12\x11\n\tblock_num\x18\x04 \x01(\x04\x12\x0f\n\x07summary\x18\x06 \x01(\x0c\"\x98\x02\n\x0fPbftMessageInfo\x12\x32\n\x08msg_type\x18\x01 \x01(\x0e\x32 .PbftMessageInfo.PbftMessageType\x12\x0c\n\x04view\x18\x02 \x01(\x04\x12\x0f\n\x07seq_num\x18\x03 \x01(\x04\x12\x11\n\tsigner_id\x18\x04 \x01(\x0c\"\x9e\x01\n\x0fPbftMessageType\x12\x13\n\x0fPRE_PREPARE_MSG\x10\x00\x12\x0f\n\x0bPREPARE_MSG\x10\x01\x12\x0e\n\nCOMMIT_MSG\x10\x02\x12\x12\n\x0e\x43HECKPOINT_MSG\x10\x03\x12\x12\n\x0eVIEWCHANGE_MSG\x10\x04\x12\x13\n\x0f\x41RBITRATION_MSG\x10\x05\x12\x18\n\x14\x41RBITRATION_DONE_MSG\x10\x06\">\n\x0bPbftMessage\x12\x1e\n\x04info\x18\x01 \x01(\x0b\x32\x10.PbftMessageInfo\x12\x0f\n\x07\x63ontent\x18\x02 \x01(\x0c\"0\n\x0ePbftViewChange\x12\x1e\n\x04info\x18\x01 \x01(\x0b\x32\x10.PbftMessageInfo\"=\n\x0bPbftNewView\x12.\n\x0cview_changes\x18\x01 \x03(\x0b\x32\x18.ConsensusPeerMessageNew\"W\n\x0ePbftSignedVote\x12\x14\n\x0cheader_bytes\x18\x01 \x01(\x0c\x12\x18\n\x10header_signature\x18\x02 \x01(\x0c\x12\x15\n\rmessage_bytes\x18\x03 \x01(\x0c\"\\\n\x08PbftSeal\x12 \n\x05\x62lock\x18\x01 \x01(\x0b\x32\x11.PbftBlockMessage\x12.\n\x0c\x63ommit_votes\x18\x02 \x03(\x0b\x32\x18.ConsensusPeerMessageNewb\x06proto3')
  ,
  dependencies=[dgt__sdk_dot_protobuf_dot_consensus__pb2.DESCRIPTOR,])



_PBFTMESSAGEINFO_PBFTMESSAGETYPE = _descriptor.EnumDescriptor(
  name='PbftMessageType',
  full_name='PbftMessageInfo.PbftMessageType',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='PRE_PREPARE_MSG', index=0, number=0,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='PREPARE_MSG', index=1, number=1,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='COMMIT_MSG', index=2, number=2,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='CHECKPOINT_MSG', index=3, number=3,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='VIEWCHANGE_MSG', index=4, number=4,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ARBITRATION_MSG', index=5, number=5,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ARBITRATION_DONE_MSG', index=6, number=6,
      serialized_options=None,
      type=None),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=291,
  serialized_end=449,
)
_sym_db.RegisterEnumDescriptor(_PBFTMESSAGEINFO_PBFTMESSAGETYPE)


_PBFTBLOCKMESSAGE = _descriptor.Descriptor(
  name='PbftBlockMessage',
  full_name='PbftBlockMessage',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='block_id', full_name='PbftBlockMessage.block_id', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='signer_id', full_name='PbftBlockMessage.signer_id', index=1,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='block_num', full_name='PbftBlockMessage.block_num', index=2,
      number=4, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='summary', full_name='PbftBlockMessage.summary', index=3,
      number=6, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
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
  serialized_start=75,
  serialized_end=166,
)


_PBFTMESSAGEINFO = _descriptor.Descriptor(
  name='PbftMessageInfo',
  full_name='PbftMessageInfo',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='msg_type', full_name='PbftMessageInfo.msg_type', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='view', full_name='PbftMessageInfo.view', index=1,
      number=2, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='seq_num', full_name='PbftMessageInfo.seq_num', index=2,
      number=3, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='signer_id', full_name='PbftMessageInfo.signer_id', index=3,
      number=4, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _PBFTMESSAGEINFO_PBFTMESSAGETYPE,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=169,
  serialized_end=449,
)


_PBFTMESSAGE = _descriptor.Descriptor(
  name='PbftMessage',
  full_name='PbftMessage',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='info', full_name='PbftMessage.info', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='content', full_name='PbftMessage.content', index=1,
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
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=451,
  serialized_end=513,
)


_PBFTVIEWCHANGE = _descriptor.Descriptor(
  name='PbftViewChange',
  full_name='PbftViewChange',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='info', full_name='PbftViewChange.info', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
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
  serialized_start=515,
  serialized_end=563,
)


_PBFTNEWVIEW = _descriptor.Descriptor(
  name='PbftNewView',
  full_name='PbftNewView',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='view_changes', full_name='PbftNewView.view_changes', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
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
  serialized_start=565,
  serialized_end=626,
)


_PBFTSIGNEDVOTE = _descriptor.Descriptor(
  name='PbftSignedVote',
  full_name='PbftSignedVote',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='header_bytes', full_name='PbftSignedVote.header_bytes', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='header_signature', full_name='PbftSignedVote.header_signature', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='message_bytes', full_name='PbftSignedVote.message_bytes', index=2,
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
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=628,
  serialized_end=715,
)


_PBFTSEAL = _descriptor.Descriptor(
  name='PbftSeal',
  full_name='PbftSeal',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='block', full_name='PbftSeal.block', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='commit_votes', full_name='PbftSeal.commit_votes', index=1,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
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
  serialized_start=717,
  serialized_end=809,
)

_PBFTMESSAGEINFO.fields_by_name['msg_type'].enum_type = _PBFTMESSAGEINFO_PBFTMESSAGETYPE
_PBFTMESSAGEINFO_PBFTMESSAGETYPE.containing_type = _PBFTMESSAGEINFO
_PBFTMESSAGE.fields_by_name['info'].message_type = _PBFTMESSAGEINFO
_PBFTVIEWCHANGE.fields_by_name['info'].message_type = _PBFTMESSAGEINFO
_PBFTNEWVIEW.fields_by_name['view_changes'].message_type = dgt__sdk_dot_protobuf_dot_consensus__pb2._CONSENSUSPEERMESSAGENEW
_PBFTSEAL.fields_by_name['block'].message_type = _PBFTBLOCKMESSAGE
_PBFTSEAL.fields_by_name['commit_votes'].message_type = dgt__sdk_dot_protobuf_dot_consensus__pb2._CONSENSUSPEERMESSAGENEW
DESCRIPTOR.message_types_by_name['PbftBlockMessage'] = _PBFTBLOCKMESSAGE
DESCRIPTOR.message_types_by_name['PbftMessageInfo'] = _PBFTMESSAGEINFO
DESCRIPTOR.message_types_by_name['PbftMessage'] = _PBFTMESSAGE
DESCRIPTOR.message_types_by_name['PbftViewChange'] = _PBFTVIEWCHANGE
DESCRIPTOR.message_types_by_name['PbftNewView'] = _PBFTNEWVIEW
DESCRIPTOR.message_types_by_name['PbftSignedVote'] = _PBFTSIGNEDVOTE
DESCRIPTOR.message_types_by_name['PbftSeal'] = _PBFTSEAL
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

PbftBlockMessage = _reflection.GeneratedProtocolMessageType('PbftBlockMessage', (_message.Message,), dict(
  DESCRIPTOR = _PBFTBLOCKMESSAGE,
  __module__ = 'dgt_sdk.protobuf.pbft_consensus_pb2'
  # @@protoc_insertion_point(class_scope:PbftBlockMessage)
  ))
_sym_db.RegisterMessage(PbftBlockMessage)

PbftMessageInfo = _reflection.GeneratedProtocolMessageType('PbftMessageInfo', (_message.Message,), dict(
  DESCRIPTOR = _PBFTMESSAGEINFO,
  __module__ = 'dgt_sdk.protobuf.pbft_consensus_pb2'
  # @@protoc_insertion_point(class_scope:PbftMessageInfo)
  ))
_sym_db.RegisterMessage(PbftMessageInfo)

PbftMessage = _reflection.GeneratedProtocolMessageType('PbftMessage', (_message.Message,), dict(
  DESCRIPTOR = _PBFTMESSAGE,
  __module__ = 'dgt_sdk.protobuf.pbft_consensus_pb2'
  # @@protoc_insertion_point(class_scope:PbftMessage)
  ))
_sym_db.RegisterMessage(PbftMessage)

PbftViewChange = _reflection.GeneratedProtocolMessageType('PbftViewChange', (_message.Message,), dict(
  DESCRIPTOR = _PBFTVIEWCHANGE,
  __module__ = 'dgt_sdk.protobuf.pbft_consensus_pb2'
  # @@protoc_insertion_point(class_scope:PbftViewChange)
  ))
_sym_db.RegisterMessage(PbftViewChange)

PbftNewView = _reflection.GeneratedProtocolMessageType('PbftNewView', (_message.Message,), dict(
  DESCRIPTOR = _PBFTNEWVIEW,
  __module__ = 'dgt_sdk.protobuf.pbft_consensus_pb2'
  # @@protoc_insertion_point(class_scope:PbftNewView)
  ))
_sym_db.RegisterMessage(PbftNewView)

PbftSignedVote = _reflection.GeneratedProtocolMessageType('PbftSignedVote', (_message.Message,), dict(
  DESCRIPTOR = _PBFTSIGNEDVOTE,
  __module__ = 'dgt_sdk.protobuf.pbft_consensus_pb2'
  # @@protoc_insertion_point(class_scope:PbftSignedVote)
  ))
_sym_db.RegisterMessage(PbftSignedVote)

PbftSeal = _reflection.GeneratedProtocolMessageType('PbftSeal', (_message.Message,), dict(
  DESCRIPTOR = _PBFTSEAL,
  __module__ = 'dgt_sdk.protobuf.pbft_consensus_pb2'
  # @@protoc_insertion_point(class_scope:PbftSeal)
  ))
_sym_db.RegisterMessage(PbftSeal)


# @@protoc_insertion_point(module_scope)
