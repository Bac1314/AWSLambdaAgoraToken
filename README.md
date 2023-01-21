# Agora Token Generator using AWS Lambda

## Description
Agora uses digital tokens to authenticate users and their privileges before they can join a channel. This project contains the python code to generate these tokens using AWS lambda function

## Prerequisites
- An Agora developer account
- A project in Agora Console with an App ID, and App Certificate.
- A Amazon Web Service (AWS Account)

## Features
If you follow the instructions below, you'll get a RESTful URL endpoint. With this URL, you'll be able to generate token for any Agora channels and UID. 

## Instructions 

### How to create the Lambda function on AWS
- Search for 'Lambda' 
- Create function
- Select 'Author from scratch'
- Basic Information -> Input the function name, select "Python 3.x" for runtime, select "x86_64" architecture
- Advanced Information -> Select "Enable Function URL" and NONE for auth type. And check "Configure for cross-region origin sharing (CORS)", then finally create function
- Copy and paste the py code to your lambda function. (Make sure to add your own Agora appId and app certificate)


### How to use the Lambda function
- Copy the function URL created above e.g. www.randomfunction.lambda-url.ap-northeast-1.on.aws
- Add the Agora channel like so "www.randomfunction.lambda-url.ap-northeast-1.on.aws/?channel=agorachannel
- It will return a json format like so {"uid":123,"token":"randomtoken"}



