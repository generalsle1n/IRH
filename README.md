# IRH

I've created a suite of some little helper tools within incident response when dealing with security breaches. These tools provide essential features for IT security professionals, making it easier to manage and respond to incidents effectively.



[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/Naereen/StrapDown.js/graphs/commit-activity)

 


## Tech Stack

**Framework:** ![.Net](https://img.shields.io/badge/.NET-5C2D91?style=for-the-badge&logo=.net&logoColor=white) 
![C#](https://img.shields.io/badge/c%23-%23239120.svg?style=for-the-badge&logo=c-sharp&logoColor=white)


**OS:** ![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Mac](https://img.shields.io/badge/mac%20os-000000?style=for-the-badge&logo=macos&logoColor=F0F0F0)





## Demo

![App Screenshot](https://raw.githubusercontent.com/generalsle1n/IRH/master/blob/AzureMFADemo.gif)


## Run Locally to Develop

Clone the project

```bash
  git clone https://github.com/generalsle1n/IRH
```

Go to the project directory

```bash
  cd IRH\IRH
```

Install dependencies

```bash
  dotnet restore
```

Build and Start the Cli Tool

```bash
  dotnet run
```


## Installation for Production Usage

Publish the project with the following settings
- Config:               ```Release```
- TargetFramework:      ```.Net 8```
- Deployment:           ```SelfContained```
- Singlefile:           ```true```
- ReadyToRun:           ```false```
- Remove not used Code: ```false```
