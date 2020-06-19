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

//
// A piece of data.
//
class Data {
public:
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
};

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