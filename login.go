// Package login is a middleware for Martini that provides a simple way to track user sessions
// in on a website. This package is loosely based on Flask-Login.
//
//        package main
//
//        func NewUser() login.User {
//            /* Generate your *MyUserModel with safe values (zero value typically) */
//            return MyUserModel
//        }
//
//        store := sessions.NewCookieStore([]byte("secret123"))
//        m := martini.Classic()
//
//        m.Use(render.Renderer())
//        m.Use(sessions.Sessions("my_session", store))
//        m.Use(SessionUser(NewUser))
//
//        m.Get("/setauth", func(session sessions.Session, user User) string {
//                err := AuthenticateSession(session, user)
//                if err != nil {
//                        t.Error(err)
//                }
//                return "OK"
//        })
//
//        m.Get("/private", LoginRequired, func(session sessions.Session, user User) string {
//                return "OK"
//        })
//
//        m.Get("/logout", LoginRequired, func(session sessions.Session, user User) string {
//                Logout(session, user)
//                return "OK"
//        })
//
// Program Flow:
// Every request to Martini will generate a new User value using the function passed to SessionUser.
// This should default to a zero value user model, and must implement the login.User interface. If
// a user exists in the request session, this user will be injected into every request handler.
// Otherwise the zero value object will be injected.
//
// When a user visits any route with the LoginRequired handler, the login.User object will be
// examined with the IsAuthenticated() function. If the user is not authenticated, they will be
// redirected to a login page (/login).
//
// To log your users in, you should set a POST route, and verify the user/password that was sent
// form the client. Due to the vast possibilities of doing this, you must be responsible for
// validating a user. Once that user is validated, call login.AuthenticateSession() to mark the
// session as authenticated.
//
// Your user type should meet the login.User interface:
//
//    type User interface {
//        // Return whether this user is logged in or not
//        IsAuthenticated() bool
//
//        // Set any flags or extra data that should be available
//	  // for a logged in user
//        Login()
//
//        // Clear any sensitive data out of the user
//        Logout()
//    }
//
// The SessionUser() Martini middleware will inject the login.User interface
// into your route handlers. These interfaces must be converted to your
// appropriate type to function correcty.
//
//    func handler(user login.User, db *MyDB) {
//        u := user.(*UserModel)
//        db.Save(u)
//    }

package login

import (
	"encoding/json"
	"github.com/codegangsta/martini"
	"github.com/codegangsta/martini-contrib/render"
	"github.com/codegangsta/martini-contrib/sessions"
	"log"
	"net/http"
)

type User interface {
	// Return whether this user is logged in or not
	IsAuthenticated() bool

	// Set any flags or extra data that should be available
	Login()

	// Clear any sensitive data out of the user
	Logout()
}

// Try to read a valid user object out of the session. Inject that object, or
// the zero value user object (from newUser) into the context.
func SessionUser(newUser func() User) martini.Handler {
	return func(s sessions.Session, c martini.Context, l *log.Logger) {
		userJson := s.Get("AUTHUSER")
		user := newUser()

		if userJson != nil {
			err := json.Unmarshal(userJson.([]byte), user)
			if err != nil {
				l.Printf("Could not unmarshal user: %v", userJson)
			} else {
				user.Login()
			}
		}

		c.MapTo(user, (*User)(nil))
	}
}

// After you have validated a user, you should call this function with the current
// session and user object. This will mark this session as authenticated and call
// the Login() method of your user object.
func AuthenticateSession(s sessions.Session, user User) error {
	user.Login()
	userJson, err := json.Marshal(user)
	s.Set("AUTHUSER", userJson)
	return err
}

// To clear out the session, call this function. Your user object's Logout()
// function will be called.
func Logout(s sessions.Session, user User) {
	user.Logout()
	s.Delete("AUTHUSER")
}

// Any routes that require a login should have this handler placed in the flow.
func LoginRequired(r render.Render, user User, w http.ResponseWriter) {
	if user.IsAuthenticated() == false {
		w.Header().Set("Location", "/login")
		r.Error(302)
		// XXX implement ?next= pattern
	}
}
