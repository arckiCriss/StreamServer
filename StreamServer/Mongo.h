#pragma once
#include <bson/bson.h>

#include <bsoncxx/document/element.hpp>
#include <bsoncxx/document/value.hpp>
#include <bsoncxx/document/view.hpp>
#include <bsoncxx/builder/core.hpp>
#include <bsoncxx/builder/stream/document.hpp>

#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>

#include <Windows.h>

class Data;
class LogData;
class AccountData;

//
// Initializes mongo.
//
VOID MongoInit(LPCSTR Uri, LPCSTR DatabaseName);

//
// Initializes a new piece of data.
//
VOID MongoNew(LPCSTR Collection, Data *Data);

//
// Saves a piece of data.
//
BOOLEAN MongoSave(LPCSTR Collection, Data *Data);

//
// Loads a piece of data.
//
BOOLEAN MongoLoadById(LPCSTR Collection, CONST std::string &UniqueId, Data *Data);

//
// Loads a piece of data.
//
BOOLEAN MongoLoadByFilter(LPCSTR Collection, bsoncxx::document::view Filter, Data *Data);

//
// A piece of data.
//
class Data {
public:
	//
	// The collection this data is in.
	//
	LPCSTR Collection;
	//
	// The unique id of this data.
	//
	std::string UniqueId;

public:
	//
	// Loads the provided document into this data.
	//
	virtual VOID Load(bsoncxx::document::value *Value) = 0;
	//
	// Saves this data into the provided document.
	//
	virtual VOID Save(bsoncxx::builder::stream::document *Value) = 0;

	//
	// Loads this data from the database.
	//
	inline VOID Load() {
		MongoLoadById(Collection, UniqueId, this);
	}

	//
	// Saves this data to the database.
	//
	inline VOID Save() {
		MongoSave(Collection, this);
	}
};

//
// A piece of log data.
//
class LogData : public Data {
public:
	//
	// The log message.
	//
	std::string Msg;

public:
	//
	// Loads the provided document into this data.
	//
	virtual VOID Load(bsoncxx::document::value *Value);
	//
	// Saves this data into the provided document.
	//
	virtual VOID Save(bsoncxx::builder::stream::document *Value);
};

//
// A piece of account data.
//
class AccountData : public Data {
public:
	//
	// The user's username.
	//
	std::string Username;
	//
	// The user's password hash.
	//
	std::string Password;

public:
	//
	// Loads the provided document into this data.
	//
	virtual VOID Load(bsoncxx::document::value *Value);
	//
	// Saves this data into the provided document.
	//
	virtual VOID Save(bsoncxx::builder::stream::document *Value);
};
