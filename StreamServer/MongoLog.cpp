#include "Mongo.h"

VOID LogData::Load(bsoncxx::document::value *Value) {
	Msg = Value->view()["Message"].get_utf8().value.to_string();
}

VOID LogData::Save(bsoncxx::builder::stream::document *Value) {
	(*Value) << "Message" << Msg;
}