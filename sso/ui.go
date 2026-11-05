package sso

import (
	"auth-proxy/config"
	"embed"
	"errors"
	"html/template"
	"net/http"
)

//go:embed assets/*
var assets embed.FS

var pages = template.Must(template.ParseFS(assets, "assets/*.html"))

func (s *Service) loginPage(w http.ResponseWriter, r *http.Request) {
	_, user, err := s.currentSSO(r)
	if err != nil && !errors.Is(err, errInvalid) {
		unavailable(w, err)
		return
	}
	if flow := r.URL.Query().Get("flow"); flow != "" {
		if user != nil {
			redirect, err := s.continuation(flow)
			if err != nil {
				http.Error(w, "Login request expired; open the application again", http.StatusBadRequest)
				return
			}
			http.Redirect(w, r, redirect, http.StatusFound)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pages.ExecuteTemplate(w, "login.html", map[string]any{"Register": config.Paths.RegisterEnabled && user == nil, "User": user}); err != nil {
		unavailable(w, err)
	}
}

func (s *Service) accountPage(w http.ResponseWriter, r *http.Request) {
	_, user, err := s.currentSSO(r)
	if errors.Is(err, errInvalid) {
		http.Redirect(w, r, "/sso/login", http.StatusFound)
		return
	}
	if err != nil {
		unavailable(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err = pages.ExecuteTemplate(w, "account.html", user); err != nil {
		unavailable(w, err)
	}
}

func (s *Service) javascript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	data, _ := assets.ReadFile("assets/passkeys.js")
	_, _ = w.Write(data)
}

func (s *Service) stylesheet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	data, _ := assets.ReadFile("assets/style.css")
	_, _ = w.Write(data)
}
