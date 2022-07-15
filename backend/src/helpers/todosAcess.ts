import * as AWS from 'aws-sdk'
import * as AWSXRay from 'aws-xray-sdk'
import { DocumentClient } from 'aws-sdk/clients/dynamodb'
import { createLogger } from '../utils/logger'
import { TodoItem } from '../models/TodoItem'
import { TodoUpdate } from '../models/TodoUpdate';
//import { S3 } from 'aws-sdk'
//import { UpdateTodoRequest } from '../requests/UpdateTodoRequest'

const XAWS = AWSXRay.captureAWS(AWS)

const logger = createLogger('TodosAccess')

const bucketName = process.env.ATTACHMENT_S3_BUCKET

// TODO: Implement the dataLayer logic

export class TodosAccess {
    constructor(
      private readonly docClient: DocumentClient = new XAWS.DynamoDB.DocumentClient(),
      private readonly todosTable = process.env.TODOS_TABLE
    ) {}
  
    async getAllTodos(userId: string): Promise<TodoItem[]> {
      logger.log({
        level: 'info',
        message: 'Getting all Todos'
      })
  
      const result = await this.docClient
        .query({
          TableName: this.todosTable,
          KeyConditionExpression: 'userId = :userId',
          ExpressionAttributeValues: {
            ':userId': userId
          },
          ScanIndexForward: false
        })
        .promise()
  
      const items = result.Items
      return items as TodoItem[]
    }
  
    async createTodo(todo: TodoItem): Promise<TodoItem> {
      logger.log({
        level: 'info',
        message: 'Creating Todo'
      })
  
      await this.docClient
        .put({
          TableName: this.todosTable,
          Item: todo
        })
        .promise()
  
      return todo
    }
  
    async updateTodo(
      todoId: string,
      userId: string,
      todoUpdate: TodoUpdate
    ): Promise<void> {
      logger.log({
        level: 'info',
        message: 'Updating Todo'
      })
      await this.docClient
        .update({
          TableName: this.todosTable,
          Key: {
            userId: userId,
            todoId: todoId
          },
          ExpressionAttributeNames: { '#N': 'name' },
          UpdateExpression: 'set #N =:n, dueDate=:d, done=:s',
          ExpressionAttributeValues: {
            ':n': todoUpdate.name,
            ':d': todoUpdate.dueDate,
            ':s': todoUpdate.done
          },
          ReturnValues: 'NONE'
        })
        .promise()
    }
  
    async deleteTodo(todoId: string, userId: string): Promise<void> {
      logger.log({
        level: 'info',
        message: 'Deleting Todo'
      })
      await this.docClient
        .delete({
          TableName: this.todosTable,
          Key: {
            userId: userId,
            todoId: todoId
          }
        })
        .promise()
    }
    async updateTodoUrl(todoId: string, userId: string): Promise<void> {
      logger.log({
        level: 'info',
        message: 'Updating Todo URL'
      })
      await this.docClient
        .update({
          TableName: this.todosTable,
          Key: {
            userId: userId,
            todoId: todoId
          },
          UpdateExpression: 'set attachmentUrl = :a',
          ExpressionAttributeValues: {
            ':a': `https://${bucketName}.s3.amazonaws.com/${todoId}`
          },
          ReturnValues: 'UPDATED_NEW'
        })
        .promise()
    }
  }