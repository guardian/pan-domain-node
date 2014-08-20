import plugins.PlayArtifact._
import sbt._
import sbt.Keys._
import play.Play.autoImport._
import PlayKeys._
import sbtassembly.Plugin.{AssemblyKeys, MergeStrategy}
import AssemblyKeys._
import Dependencies._


object PanDomainAuthenticationBuild extends Build {

  val commonSettings =
    Seq(
      scalaVersion := "2.11.1",
      scalaVersion in ThisBuild := "2.11.1",
      crossScalaVersions := Seq("2.10.4", "2.11.1"),
      organization := "com.gu",
      version      := "0.1-SNAPSHOT",
      fork in Test := false,
      resolvers ++= Seq("Typesafe Repository" at "http://repo.typesafe.com/typesafe/releases/"),
      scalacOptions ++= Seq("-feature", "-deprecation", "-language:higherKinds", "-Xfatal-warnings")
    )

  lazy val panDomainAuthCore = project("pan-domain-auth-core")
    .settings(
      libraryDependencies ++= akkaDependencies ++ awsDependencies ++ gdataDependencies
    )

  lazy val panDomainAuthPlay = project("pan-domain-auth-play")
    .settings(
      libraryDependencies ++= playLibs
    ).dependsOn(panDomainAuthCore)

  lazy val exampleApp = playProject("pan-domain-auth-example")
                  .settings(libraryDependencies ++= awsDependencies)
                  .settings(playDefaultPort := 9500)
                  .dependsOn(panDomainAuthPlay)

  def project(path: String): Project =
    Project(path, file(path)).settings(commonSettings: _*)

  def playProject(path: String): Project =
    Project(path, file(path)).enablePlugins(play.PlayScala)
      .settings(commonSettings ++ playArtifactDistSettings ++ playArtifactSettings: _*)
      .settings(libraryDependencies += ws)
      .settings(magentaPackageName := path)

  def playArtifactSettings = Seq(
    ivyXML :=
      <dependencies>
        <exclude org="commons-logging"/>
        <exclude org="org.springframework"/>
        <exclude org="org.scala-tools.sbt"/>
      </dependencies>,
    mergeStrategy in assembly <<= (mergeStrategy in assembly) { old => {
      case f if f.startsWith("org/apache/lucene/index/") => MergeStrategy.first
      case "play/core/server/ServerWithStop.class" => MergeStrategy.first
      case "ehcache.xml" => MergeStrategy.first
      case x => old(x)
    }}
  )

}
