#include "Mongo.h"

VOID AccountData::Load(bsoncxx::document::value *Value) {
	Username = Value->view()["Username"].get_utf8().value.to_string();
	Password = Value->view()["Password"].get_utf8().value.to_string();
}

VOID AccountData::Save(bsoncxx::builder::stream::document *Value) {
	(*Value) << "Username" << Username;
	(*Value) << "Password" << Password;
}