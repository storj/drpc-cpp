// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: sesamestreet.proto

#include "sesamestreet.pb.h"

#include <algorithm>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>

PROTOBUF_PRAGMA_INIT_SEG
namespace sesamestreet {
constexpr Cookie::Cookie(
  ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized)
  : type_(0)
{}
struct CookieDefaultTypeInternal {
  constexpr CookieDefaultTypeInternal()
    : _instance(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized{}) {}
  ~CookieDefaultTypeInternal() {}
  union {
    Cookie _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT CookieDefaultTypeInternal _Cookie_default_instance_;
constexpr Crumbs::Crumbs(
  ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized)
  : cookie_(nullptr){}
struct CrumbsDefaultTypeInternal {
  constexpr CrumbsDefaultTypeInternal()
    : _instance(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized{}) {}
  ~CrumbsDefaultTypeInternal() {}
  union {
    Crumbs _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT CrumbsDefaultTypeInternal _Crumbs_default_instance_;
}  // namespace sesamestreet
static ::PROTOBUF_NAMESPACE_ID::Metadata file_level_metadata_sesamestreet_2eproto[2];
static const ::PROTOBUF_NAMESPACE_ID::EnumDescriptor* file_level_enum_descriptors_sesamestreet_2eproto[1];
static constexpr ::PROTOBUF_NAMESPACE_ID::ServiceDescriptor const** file_level_service_descriptors_sesamestreet_2eproto = nullptr;

const ::PROTOBUF_NAMESPACE_ID::uint32 TableStruct_sesamestreet_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::sesamestreet::Cookie, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  PROTOBUF_FIELD_OFFSET(::sesamestreet::Cookie, type_),
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::sesamestreet::Crumbs, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  PROTOBUF_FIELD_OFFSET(::sesamestreet::Crumbs, cookie_),
};
static const ::PROTOBUF_NAMESPACE_ID::internal::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, sizeof(::sesamestreet::Cookie)},
  { 6, -1, sizeof(::sesamestreet::Crumbs)},
};

static ::PROTOBUF_NAMESPACE_ID::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::sesamestreet::_Cookie_default_instance_),
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::sesamestreet::_Crumbs_default_instance_),
};

const char descriptor_table_protodef_sesamestreet_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) =
  "\n\022sesamestreet.proto\022\014sesamestreet\"`\n\006Co"
  "okie\022\'\n\004type\030\001 \001(\0162\031.sesamestreet.Cookie"
  ".Type\"-\n\004Type\022\t\n\005Sugar\020\000\022\013\n\007Oatmeal\020\001\022\r\n"
  "\tChocolate\020\002\".\n\006Crumbs\022$\n\006cookie\030\001 \001(\0132\024"
  ".sesamestreet.Cookie2J\n\rCookieMonster\0229\n"
  "\tEatCookie\022\024.sesamestreet.Cookie\032\024.sesam"
  "estreet.Crumbs\"\000B Z\036storj.io/drpc/exampl"
  "es/drpc/pbb\006proto3"
  ;
static ::PROTOBUF_NAMESPACE_ID::internal::once_flag descriptor_table_sesamestreet_2eproto_once;
const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_sesamestreet_2eproto = {
  false, false, 298, descriptor_table_protodef_sesamestreet_2eproto, "sesamestreet.proto", 
  &descriptor_table_sesamestreet_2eproto_once, nullptr, 0, 2,
  schemas, file_default_instances, TableStruct_sesamestreet_2eproto::offsets,
  file_level_metadata_sesamestreet_2eproto, file_level_enum_descriptors_sesamestreet_2eproto, file_level_service_descriptors_sesamestreet_2eproto,
};
PROTOBUF_ATTRIBUTE_WEAK const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable* descriptor_table_sesamestreet_2eproto_getter() {
  return &descriptor_table_sesamestreet_2eproto;
}

// Force running AddDescriptors() at dynamic initialization time.
PROTOBUF_ATTRIBUTE_INIT_PRIORITY static ::PROTOBUF_NAMESPACE_ID::internal::AddDescriptorsRunner dynamic_init_dummy_sesamestreet_2eproto(&descriptor_table_sesamestreet_2eproto);
namespace sesamestreet {
const ::PROTOBUF_NAMESPACE_ID::EnumDescriptor* Cookie_Type_descriptor() {
  ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(&descriptor_table_sesamestreet_2eproto);
  return file_level_enum_descriptors_sesamestreet_2eproto[0];
}
bool Cookie_Type_IsValid(int value) {
  switch (value) {
    case 0:
    case 1:
    case 2:
      return true;
    default:
      return false;
  }
}

#if (__cplusplus < 201703) && (!defined(_MSC_VER) || _MSC_VER >= 1900)
constexpr Cookie_Type Cookie::Sugar;
constexpr Cookie_Type Cookie::Oatmeal;
constexpr Cookie_Type Cookie::Chocolate;
constexpr Cookie_Type Cookie::Type_MIN;
constexpr Cookie_Type Cookie::Type_MAX;
constexpr int Cookie::Type_ARRAYSIZE;
#endif  // (__cplusplus < 201703) && (!defined(_MSC_VER) || _MSC_VER >= 1900)

// ===================================================================

class Cookie::_Internal {
 public:
};

Cookie::Cookie(::PROTOBUF_NAMESPACE_ID::Arena* arena)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena) {
  SharedCtor();
  RegisterArenaDtor(arena);
  // @@protoc_insertion_point(arena_constructor:sesamestreet.Cookie)
}
Cookie::Cookie(const Cookie& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  type_ = from.type_;
  // @@protoc_insertion_point(copy_constructor:sesamestreet.Cookie)
}

void Cookie::SharedCtor() {
type_ = 0;
}

Cookie::~Cookie() {
  // @@protoc_insertion_point(destructor:sesamestreet.Cookie)
  SharedDtor();
  _internal_metadata_.Delete<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

void Cookie::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
}

void Cookie::ArenaDtor(void* object) {
  Cookie* _this = reinterpret_cast< Cookie* >(object);
  (void)_this;
}
void Cookie::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void Cookie::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}

void Cookie::Clear() {
// @@protoc_insertion_point(message_clear_start:sesamestreet.Cookie)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  type_ = 0;
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* Cookie::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // .sesamestreet.Cookie.Type type = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 8)) {
          ::PROTOBUF_NAMESPACE_ID::uint64 val = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
          _internal_set_type(static_cast<::sesamestreet::Cookie_Type>(val));
        } else goto handle_unusual;
        continue;
      default: {
      handle_unusual:
        if ((tag == 0) || ((tag & 7) == 4)) {
          CHK_(ptr);
          ctx->SetLastTag(tag);
          goto success;
        }
        ptr = UnknownFieldParse(tag,
            _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
            ptr, ctx);
        CHK_(ptr != nullptr);
        continue;
      }
    }  // switch
  }  // while
success:
  return ptr;
failure:
  ptr = nullptr;
  goto success;
#undef CHK_
}

::PROTOBUF_NAMESPACE_ID::uint8* Cookie::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:sesamestreet.Cookie)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // .sesamestreet.Cookie.Type type = 1;
  if (this->type() != 0) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteEnumToArray(
      1, this->_internal_type(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:sesamestreet.Cookie)
  return target;
}

size_t Cookie::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:sesamestreet.Cookie)
  size_t total_size = 0;

  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // .sesamestreet.Cookie.Type type = 1;
  if (this->type() != 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::EnumSize(this->_internal_type());
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    return ::PROTOBUF_NAMESPACE_ID::internal::ComputeUnknownFieldsSize(
        _internal_metadata_, total_size, &_cached_size_);
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void Cookie::MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:sesamestreet.Cookie)
  GOOGLE_DCHECK_NE(&from, this);
  const Cookie* source =
      ::PROTOBUF_NAMESPACE_ID::DynamicCastToGenerated<Cookie>(
          &from);
  if (source == nullptr) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:sesamestreet.Cookie)
    ::PROTOBUF_NAMESPACE_ID::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:sesamestreet.Cookie)
    MergeFrom(*source);
  }
}

void Cookie::MergeFrom(const Cookie& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:sesamestreet.Cookie)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (from.type() != 0) {
    _internal_set_type(from._internal_type());
  }
}

void Cookie::CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:sesamestreet.Cookie)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void Cookie::CopyFrom(const Cookie& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:sesamestreet.Cookie)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool Cookie::IsInitialized() const {
  return true;
}

void Cookie::InternalSwap(Cookie* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  swap(type_, other->type_);
}

::PROTOBUF_NAMESPACE_ID::Metadata Cookie::GetMetadata() const {
  return ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(
      &descriptor_table_sesamestreet_2eproto_getter, &descriptor_table_sesamestreet_2eproto_once,
      file_level_metadata_sesamestreet_2eproto[0]);
}

// ===================================================================

class Crumbs::_Internal {
 public:
  static const ::sesamestreet::Cookie& cookie(const Crumbs* msg);
};

const ::sesamestreet::Cookie&
Crumbs::_Internal::cookie(const Crumbs* msg) {
  return *msg->cookie_;
}
Crumbs::Crumbs(::PROTOBUF_NAMESPACE_ID::Arena* arena)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena) {
  SharedCtor();
  RegisterArenaDtor(arena);
  // @@protoc_insertion_point(arena_constructor:sesamestreet.Crumbs)
}
Crumbs::Crumbs(const Crumbs& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  if (from._internal_has_cookie()) {
    cookie_ = new ::sesamestreet::Cookie(*from.cookie_);
  } else {
    cookie_ = nullptr;
  }
  // @@protoc_insertion_point(copy_constructor:sesamestreet.Crumbs)
}

void Crumbs::SharedCtor() {
cookie_ = nullptr;
}

Crumbs::~Crumbs() {
  // @@protoc_insertion_point(destructor:sesamestreet.Crumbs)
  SharedDtor();
  _internal_metadata_.Delete<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

void Crumbs::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  if (this != internal_default_instance()) delete cookie_;
}

void Crumbs::ArenaDtor(void* object) {
  Crumbs* _this = reinterpret_cast< Crumbs* >(object);
  (void)_this;
}
void Crumbs::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void Crumbs::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}

void Crumbs::Clear() {
// @@protoc_insertion_point(message_clear_start:sesamestreet.Crumbs)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  if (GetArenaForAllocation() == nullptr && cookie_ != nullptr) {
    delete cookie_;
  }
  cookie_ = nullptr;
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* Crumbs::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // .sesamestreet.Cookie cookie = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 10)) {
          ptr = ctx->ParseMessage(_internal_mutable_cookie(), ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      default: {
      handle_unusual:
        if ((tag == 0) || ((tag & 7) == 4)) {
          CHK_(ptr);
          ctx->SetLastTag(tag);
          goto success;
        }
        ptr = UnknownFieldParse(tag,
            _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
            ptr, ctx);
        CHK_(ptr != nullptr);
        continue;
      }
    }  // switch
  }  // while
success:
  return ptr;
failure:
  ptr = nullptr;
  goto success;
#undef CHK_
}

::PROTOBUF_NAMESPACE_ID::uint8* Crumbs::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:sesamestreet.Crumbs)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // .sesamestreet.Cookie cookie = 1;
  if (this->has_cookie()) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(
        1, _Internal::cookie(this), target, stream);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:sesamestreet.Crumbs)
  return target;
}

size_t Crumbs::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:sesamestreet.Crumbs)
  size_t total_size = 0;

  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // .sesamestreet.Cookie cookie = 1;
  if (this->has_cookie()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
        *cookie_);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    return ::PROTOBUF_NAMESPACE_ID::internal::ComputeUnknownFieldsSize(
        _internal_metadata_, total_size, &_cached_size_);
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void Crumbs::MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:sesamestreet.Crumbs)
  GOOGLE_DCHECK_NE(&from, this);
  const Crumbs* source =
      ::PROTOBUF_NAMESPACE_ID::DynamicCastToGenerated<Crumbs>(
          &from);
  if (source == nullptr) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:sesamestreet.Crumbs)
    ::PROTOBUF_NAMESPACE_ID::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:sesamestreet.Crumbs)
    MergeFrom(*source);
  }
}

void Crumbs::MergeFrom(const Crumbs& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:sesamestreet.Crumbs)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (from.has_cookie()) {
    _internal_mutable_cookie()->::sesamestreet::Cookie::MergeFrom(from._internal_cookie());
  }
}

void Crumbs::CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:sesamestreet.Crumbs)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void Crumbs::CopyFrom(const Crumbs& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:sesamestreet.Crumbs)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool Crumbs::IsInitialized() const {
  return true;
}

void Crumbs::InternalSwap(Crumbs* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  swap(cookie_, other->cookie_);
}

::PROTOBUF_NAMESPACE_ID::Metadata Crumbs::GetMetadata() const {
  return ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(
      &descriptor_table_sesamestreet_2eproto_getter, &descriptor_table_sesamestreet_2eproto_once,
      file_level_metadata_sesamestreet_2eproto[1]);
}

// @@protoc_insertion_point(namespace_scope)
}  // namespace sesamestreet
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::sesamestreet::Cookie* Arena::CreateMaybeMessage< ::sesamestreet::Cookie >(Arena* arena) {
  return Arena::CreateMessageInternal< ::sesamestreet::Cookie >(arena);
}
template<> PROTOBUF_NOINLINE ::sesamestreet::Crumbs* Arena::CreateMaybeMessage< ::sesamestreet::Crumbs >(Arena* arena) {
  return Arena::CreateMessageInternal< ::sesamestreet::Crumbs >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>