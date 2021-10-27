package Data

import java.time.LocalDateTime

object DatabaseContext {

  import com.zaxxer.hikari.{HikariConfig, HikariDataSource}
  import io.getquill._

  val pgDataSource = new org.postgresql.ds.PGSimpleDataSource()
  pgDataSource.setUser("scala")
  pgDataSource.setPassword("scala")
  pgDataSource.setDatabaseName("BotTender")
  pgDataSource.setPortNumbers(Array(5436))

  val hikariConfig = new HikariConfig()
  hikariConfig.setDataSource(pgDataSource)

  lazy val ctx = new PostgresJdbcContext(LowerCase, new HikariDataSource(hikariConfig))

  case class Account(userId: Long, username: String, balance: Double, active: Boolean)
  case class ExprType(exprTypeId: Long, name: String)
  case class Message(messageId: Long, userId: Long, content: String, createdDate: LocalDateTime, exprTypeId: Option[Long], replyToId: Option[Long], mentionId: Option[Long])
}
