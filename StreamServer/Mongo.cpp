#include "Mongo.h"
#include "Logging.h"

//
// Config stuff.
//
static mongocxx::instance Instance = {};
static mongocxx::uri RemoteUri;
static mongocxx::client Client;
static mongocxx::database Db;

//
// Collections, which we store our data in..
//
static mongocxx::collection Accounts;
static mongocxx::collection Logs;

VOID MongoInit(LPCSTR Uri, LPCSTR DatabaseName) {
	LOG("Creating URI");
	RemoteUri = mongocxx::uri(Uri);

	LOG("Creating client");
	Client = mongocxx::client(RemoteUri);
	Db = Client[DatabaseName];

	LOG("Retrieving databases");
	Accounts = Db["Accounts"];
	Logs = Db["Logs"];
}

VOID MongoNew(LPCSTR Collection, Data *Data) {
	//
	// Insert an empty document.
	//
	bsoncxx::builder::stream::document Document;
	auto Result = Db[Collection].insert_one(Document.view());

	//
	// Store the new unique id in our data.
	//
	Data->UniqueId = Result->inserted_id().get_oid().value.to_string();
}

BOOLEAN MongoSave(LPCSTR Collection, Data *Data) {
	//
	// Generate the new document.
	//
	bsoncxx::builder::stream::document Document;
	Document << "_id" << bsoncxx::oid{ Data->UniqueId };
	Data->Save(&Document);

	//
	// Generate the replacement filter.
	//
	bsoncxx::builder::stream::document Filter;
	Filter << "_id" << bsoncxx::oid{ Data->UniqueId };

	//
	// Perform the replace.
	//
	Db[Collection].find_one_and_replace(Filter.view(), Document.view());
	return TRUE;

}

BOOLEAN MongoLoadById(LPCSTR Collection, CONST std::string &UniqueId, Data *Data) {
	//
	// Generate the find filter.
	//
	bsoncxx::builder::stream::document Filter;
	Filter << "_id" << UniqueId;

	//
	// Attempt to find it.
	//
	auto Found = Db[Collection].find_one(Filter.view());
	if (!Found.has_value()) {
		return FALSE;
	}

	//
	// If we found it, load it into our data object.
	//
	Data->Load(Found.get_ptr());
	return TRUE;
}

BOOLEAN MongoLoadByFilter(LPCSTR Collection, bsoncxx::document::view Filter, Data *Data) {
	//
	// Attempt to find it.
	//
	auto Found = Db[Collection].find_one(Filter);
	if (!Found.has_value()) {
		return FALSE;
	}

	//
	// If we found it, load it into our data object.
	//
	Data->Load(Found.get_ptr());
	return TRUE;
}