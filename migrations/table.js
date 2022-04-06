"use strict";

const { dynamoDB, documentClient } = require("../config/db");
const dbSchema = require("../schemas/db");
const backoffInterval = 5000;

const checkTableStatus = async (tableName) => {
  try {
    const { Table } = await dynamoDB
      .describeTable({ TableName: tableName })
      .promise();

    return Table.TableStatus;
  } catch (error) {
    console.log(error);
  }
};

const waitForTable = async (tableName) => {
  try {
    const tableStatus = await checkTableStatus(tableName);

    if (tableStatus !== "ACTIVE") {
      console.log(
        `Table status: ${tableStatus}, retrying in ${backoffInterval}ms...`
      );
      return new Promise((resolve) => {
        setTimeout(() => waitForTable().then(resolve), backoffInterval);
      });
    }
    return `Table ${tableName} is ACTIVE.`;
  } catch (error) {
    console.log(
      `Table not found! Error below. Retrying in ${backoffInterval} ms...`,
      error
    );
    return new Promise((resolve) => {
      setTimeout(() => waitForTable().then(resolve), backoffInterval);
    });
  }
};

const createTable = async (tableSchema) => {
  try {
    const { TableNames } = await dynamoDB.listTables().promise();

    if (TableNames.includes(tableSchema.TableName)) {
      return `Table ${tableSchema.TableName} already exists.`;
    }

    await dynamoDB.createTable(tableSchema).promise();
    await waitForTable(tableSchema.TableName);
  } catch (error) {
    console.log(error);
  }
};

const deleteTable = async (tableName) => {
  try {
    const { TableNames } = await dynamoDB.listTables().promise();

    if (TableNames.includes(tableName) === false) {
      return `Table ${tableName} does not exist.`;
    }

    const tableStatus = await checkTableStatus(tableName);

    if (tableStatus !== "ACTIVE") {
      return `Cannot delete Table ${tableName} as it is in ${tableStatus} state.`;
    }

    await dynamoDB.deleteTable({ TableName: tableName }).promise();
    return `Table ${tableName} deleted successfully.`;
  } catch (error) {
    console.log(error);
  }
};

module.exports = {
  checkTableStatus,
  createTable,
  deleteTable,
  waitForTable,
};
