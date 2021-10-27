ThisBuild / useCoursier := false

name := "Bot-tender"

version := "0.1"

scalaVersion := "2.13.1"

libraryDependencies += "io.getquill" %% "quill-jdbc" % "3.5.1"
libraryDependencies += "org.postgresql" % "postgresql" % "42.2.12"

libraryDependencies += "com.lihaoyi" %% "scalatags" % "0.9.0"
libraryDependencies += "com.lihaoyi" %% "cask" % "0.6.0"
