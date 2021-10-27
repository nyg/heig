package Web

import Data.UsersInfo

/**
  * Assembles the custom decorators.
  */
object Decorators {
    /**
      * Wrap an endpoint. Read the request to search for the session user in
      * the cookies. Provide the endpoint with `Some(user)` if there exists a
      * valid session user. And `None` otherwise.      *
      */
    class loggedIn extends cask.RawDecorator {
        def wrapFunction(ctx: cask.Request, delegate: Delegate) = {
            val user = ctx.cookies.get("username")
                .map(c => c.value)
                .filter(u => UsersInfo.doesAccountExist(u))
            delegate(Map("user" -> user))
        }
    }
}
