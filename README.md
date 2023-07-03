# 基于Hash算法的分组加密软件

## Introduction

### Summary 

本软件是一款基于三重Feistel结构Hash算法的分组加密软件，使用PyQt5和Pyinstaller开发。

### Features

- 支持多种常见Hash算法，如MD5、SHA系列、SM3等
- 支持自定义分组长度
- 能检测多种输入错误
- 适配各语言文本
- 可以通过日志查看加密情况

## Requirements

本软件由于采用exe可执行文件方式启动，仅支持Windows系统运行。

## Usage

解压压缩包，启动dist/main.exe即可使用。

## Development

开发流程：使用PyQt5进行算法和GUI开发，使用Pyinstaller将项目转为可执行文件。

项目结构：main.py，GUI.py，sm3.py

- main.py  ——主文件，同时作为逻辑设计文件定义了各种信号和槽
- GUI.py   ——图形界面文件，定义了图形界面
- sm3.py   ——自己写的SM3算法，在主文件中调用

## Contact

联系方式：

- QQ：731353921
- 微信：songvip02
- 北航邮箱：20373551@buaa.edu.cn
