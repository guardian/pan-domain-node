package com.gu.pandomainauth

import com.gu.pandomainauth.model._
import com.gu.pandomainauth.service.CookieUtils

import java.security.PublicKey


object PanDomain {
  /**
   * Check the authentication status of the provided credentials by examining the signed cookie data.
   */
  def authStatus(cookieData: String, publicKey: PublicKey, validateUser: AuthenticatedUser => Boolean,
                 apiGracePeriod: Long, system: String, cacheValidation: Boolean, forceExpiry: Boolean): AuthenticationStatus = {
    CookieUtils.parseCookieData(cookieData, publicKey).fold(InvalidCookie, { authedUser =>
      checkStatus(authedUser, validateUser, apiGracePeriod, system, cacheValidation, forceExpiry)
    })
  }

  private def checkStatus(authedUser: AuthenticatedUser, validateUser: AuthenticatedUser => Boolean,
                          apiGracePeriod: Long, system: String, cacheValidation: Boolean,
                          forceExpiry: Boolean): AuthenticationStatus = {

    if (authedUser.isExpired && authedUser.isInGracePeriod(apiGracePeriod)) {
      // expired, but in grace period - check user is valid, GracePeriod if so
      if (cacheValidation && authedUser.authenticatedIn(system)) {
        // if validation is cached, check user has been validated here
        GracePeriod(authedUser)
      } else if (validateUser(authedUser)) {
        // validation says this user is ok
        GracePeriod(authedUser)
      } else {
        // the user is in the grace period but has failed validation
        NotAuthorized(authedUser)
      }
    } else if (authedUser.isExpired || forceExpiry) {
      // expired and outside grace period
      Expired(authedUser)
    } else if (cacheValidation && authedUser.authenticatedIn(system)) {
      // if cacheValidation is enabled, check the user was validated here
      Authenticated(authedUser)
    } else if (validateUser(authedUser)) {
      // fresh validation says the user is valid
      Authenticated(authedUser)
    } else {
      // user has not expired but has failed validation checks
      NotAuthorized(authedUser)
    }
  }

  val guardianValidation: AuthenticatedUser => Boolean = { authedUser =>
    (authedUser.user.emailDomain == "guardian.co.uk") && authedUser.multiFactor
  }
}
