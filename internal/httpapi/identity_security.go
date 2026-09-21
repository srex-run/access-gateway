package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/emicklei/go-restful/v3"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/service"
)

type MFAService interface {
	BeginMFA(context.Context, domain.User, bool) (*service.PendingMFA, error)
	GetMFAChallenge(context.Context, string) (service.PendingMFA, error)
	StartMFAEnrollment(context.Context, string) (service.MFAEnrollment, error)
	CompleteMFA(context.Context, string, string, string) (service.MFAResult, error)
	GetMFAStatus(context.Context, string) (service.MFAStatus, error)
	ValidateMFASession(context.Context, string, bool) error
	UpdateOwnMFA(context.Context, string, int64, string, bool) (service.MFAResult, error)
	ResetUserMFA(context.Context, string, string) error
}

type InvitationService interface {
	CreateInvitation(context.Context, string, service.CreateInvitationInput) (service.CreatedInvitation, error)
	ListInvitations(context.Context, string, int, int) ([]repository.InvitationView, error)
	ResendInvitation(context.Context, string, string) (service.CreatedInvitation, error)
	RevokeInvitation(context.Context, string, string) error
	PreviewInvitation(context.Context, string) (service.InvitationPreview, error)
	AcceptInvitation(context.Context, string, string) (domain.User, error)
}

const mfaCookieName = "access_gateway_mfa"

func (s *Server) registerIdentitySecurity(ws *restful.WebService) {
	ws.Route(ws.GET("/auth/mfa").To(s.mfaChallenge))
	ws.Route(ws.POST("/auth/mfa/enroll").To(s.enrollMFA))
	ws.Route(ws.POST("/auth/mfa/confirm").To(s.confirmMFA))
	ws.Route(ws.POST("/auth/mfa/verify").To(s.verifyMFA))
	ws.Route(ws.GET("/auth/account/mfa").To(s.myMFA))
	ws.Route(ws.POST("/auth/account/mfa/enroll").To(s.enrollOwnMFA))
	ws.Route(ws.POST("/auth/account/mfa/recovery-codes").To(s.regenerateRecoveryCodes))
	ws.Route(ws.POST("/auth/account/mfa/unbind").To(s.unbindMFA))
	ws.Route(ws.GET("/admin/users/{user_id}/mfa").To(s.userMFA))
	ws.Route(ws.DELETE("/admin/users/{user_id}/mfa").AllowedMethodsWithoutContentType([]string{http.MethodDelete}).To(s.resetMFA))
	ws.Route(ws.GET("/admin/invitations").To(s.listInvitations))
	ws.Route(ws.POST("/admin/invitations").To(s.createInvitation))
	ws.Route(ws.POST("/admin/invitations/{invitation_id}/resend").To(s.resendInvitation))
	ws.Route(ws.DELETE("/admin/invitations/{invitation_id}").AllowedMethodsWithoutContentType([]string{http.MethodDelete}).To(s.revokeInvitation))
	ws.Route(ws.POST("/auth/invitation/preview").To(s.previewInvitation))
	ws.Route(ws.POST("/auth/invitation/accept").To(s.acceptInvitation))
}

func (s *Server) setPendingMFA(request *restful.Request, response *restful.Response, pending *service.PendingMFA) {
	// Include the transport challenge endpoint; this cookie is never accepted as a normal session.
	http.SetCookie(response.ResponseWriter, &http.Cookie{Name: mfaCookieName, Value: pending.Token, Path: "/api/v1/auth", MaxAge: 300, HttpOnly: true, Secure: s.secureRequest(request.Request), SameSite: http.SameSiteStrictMode})
	s.clearSessionCookie(request, response)
}

func (s *Server) clearPendingMFA(request *restful.Request, response *restful.Response) {
	if _, err := request.Request.Cookie(mfaCookieName); err != nil {
		return
	}
	http.SetCookie(response.ResponseWriter, &http.Cookie{Name: mfaCookieName, Path: "/api/v1/auth", MaxAge: -1, HttpOnly: true, Secure: s.secureRequest(request.Request), SameSite: http.SameSiteStrictMode})
}

func (s *Server) clearSessionCookie(request *restful.Request, response *restful.Response) {
	http.SetCookie(response.ResponseWriter, &http.Cookie{Name: s.SessionCookieName, Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secureRequest(request.Request), SameSite: http.SameSiteLaxMode})
}

// All first-factor success paths must pass through this gate, including invitation acceptance.
func (s *Server) finishPrimaryLogin(request *restful.Request, response *restful.Response, user domain.User, redirect bool) {
	if s.MFA == nil && s.authRuntime(request.Request.Context()).MFA.Required(false, true) {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	if s.MFA != nil {
		pending, err := s.MFA.BeginMFA(request.Request.Context(), user, false)
		if err != nil {
			s.writeError(response, err)
			return
		}
		if pending != nil {
			s.setPendingMFA(request, response, pending)
			if redirect {
				response.Header().Set("Location", "/mfa")
				response.WriteHeader(http.StatusFound)
			} else {
				_ = response.WriteEntity(pending)
			}
			return
		}
	}
	s.clearPendingMFA(request, response)
	s.setSessionCookie(request, response, user)
	if redirect {
		response.Header().Set("Location", s.FrontendRedirect)
		response.WriteHeader(http.StatusFound)
	} else {
		_ = response.WriteEntity(map[string]string{"user_id": user.ID})
	}
}

func (s *Server) pendingToken(request *restful.Request, response *restful.Response) (string, bool) {
	if s.MFA == nil {
		s.writeError(response, service.ErrNotConfigured)
		return "", false
	}
	cookie, err := request.Request.Cookie(mfaCookieName)
	if err != nil || len(cookie.Value) != 43 {
		s.writeError(response, service.ErrMFAFailed)
		return "", false
	}
	return cookie.Value, true
}

func (s *Server) mfaChallenge(request *restful.Request, response *restful.Response) {
	token, ok := s.pendingToken(request, response)
	if !ok {
		return
	}
	value, err := s.MFA.GetMFAChallenge(request.Request.Context(), token)
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(value)
}

func (s *Server) enrollMFA(request *restful.Request, response *restful.Response) {
	token, ok := s.pendingToken(request, response)
	if !ok || !s.allowPasswordAttempt(request, response, "mfa-enroll:"+token) {
		return
	}
	value, err := s.MFA.StartMFAEnrollment(request.Request.Context(), token)
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(value)
}

func (s *Server) confirmMFA(request *restful.Request, response *restful.Response) {
	s.completeMFA(request, response, "enroll")
}
func (s *Server) verifyMFA(request *restful.Request, response *restful.Response) {
	s.completeMFA(request, response, "verify")
}

func (s *Server) completeMFA(request *restful.Request, response *restful.Response, kind string) {
	token, ok := s.pendingToken(request, response)
	if !ok || !s.allowPasswordAttempt(request, response, "mfa:"+token) {
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, service.ErrMFAFailed)
		return
	}
	value, err := s.MFA.CompleteMFA(request.Request.Context(), token, body.Code, kind)
	if err != nil {
		s.writeError(response, err)
		return
	}
	s.clearPendingMFA(request, response)
	s.setVerifiedSession(request, response, value.User)
	_ = response.WriteEntity(struct {
		UserID string   `json:"user_id"`
		Codes  []string `json:"codes,omitempty"`
	}{value.User.ID, value.Codes})
}

func (s *Server) setVerifiedSession(request *restful.Request, response *restful.Response, user domain.User) {
	http.SetCookie(response.ResponseWriter, &http.Cookie{Name: s.SessionCookieName, Value: s.SessionSigner.SignMFA(user.ID, user.AuthVersion, time.Now().Add(8*time.Hour)), Path: "/", MaxAge: 8 * 60 * 60, HttpOnly: true, Secure: s.secureRequest(request.Request), SameSite: http.SameSiteLaxMode})
}

func (s *Server) mfaSession(request *restful.Request, response *restful.Response) (domain.User, bool) {
	if s.MFA == nil || s.SessionSigner == nil {
		s.writeError(response, service.ErrNotConfigured)
		return domain.User{}, false
	}
	id, ok := s.currentUser(request, response)
	if !ok {
		return domain.User{}, false
	}
	cookie, err := request.Request.Cookie(s.SessionCookieName)
	if err != nil {
		s.writeError(response, errUnauthenticated)
		return domain.User{}, false
	}
	userID, version, valid := s.SessionSigner.VerifyVersioned(cookie.Value, time.Now())
	if !valid || userID != id {
		s.writeError(response, errUnauthenticated)
		return domain.User{}, false
	}
	return domain.User{ID: id, AuthVersion: version}, true
}

func (s *Server) myMFA(request *restful.Request, response *restful.Response) {
	user, ok := s.mfaSession(request, response)
	if !ok {
		return
	}
	value, err := s.MFA.GetMFAStatus(request.Request.Context(), user.ID)
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(value)
}

func (s *Server) enrollOwnMFA(request *restful.Request, response *restful.Response) {
	user, ok := s.mfaSession(request, response)
	if !ok || !s.allowPasswordAttempt(request, response, "mfa-self:"+user.ID) {
		return
	}
	value, err := s.MFA.BeginMFA(request.Request.Context(), user, true)
	if err != nil {
		s.writeError(response, err)
		return
	}
	s.setPendingMFA(request, response, value)
	_ = response.WriteEntity(value)
}

func (s *Server) regenerateRecoveryCodes(request *restful.Request, response *restful.Response) {
	s.updateOwnMFA(request, response, false)
}
func (s *Server) unbindMFA(request *restful.Request, response *restful.Response) {
	s.updateOwnMFA(request, response, true)
}

func (s *Server) updateOwnMFA(request *restful.Request, response *restful.Response, remove bool) {
	user, ok := s.mfaSession(request, response)
	if !ok || !s.allowPasswordAttempt(request, response, "mfa-self:"+user.ID) {
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, service.ErrMFAFailed)
		return
	}
	value, err := s.MFA.UpdateOwnMFA(request.Request.Context(), user.ID, user.AuthVersion, body.Code, remove)
	if err != nil {
		s.writeError(response, err)
		return
	}
	if remove {
		s.logout(request, response)
		return
	}
	s.setVerifiedSession(request, response, value.User)
	_ = response.WriteEntity(value)
}

func (s *Server) userMFA(request *restful.Request, response *restful.Response) {
	if s.MFA == nil {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	value, err := s.MFA.GetMFAStatus(request.Request.Context(), request.PathParameter("user_id"))
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(struct {
		Bound bool `json:"bound"`
	}{value.Bound})
}

func (s *Server) resetMFA(request *restful.Request, response *restful.Response) {
	if s.MFA == nil {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	actor, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	if err := s.MFA.ResetUserMFA(request.Request.Context(), actor, request.PathParameter("user_id")); err != nil {
		s.writeError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (s *Server) invitationActor(request *restful.Request, response *restful.Response) (string, bool) {
	if s.Invitations == nil {
		s.writeError(response, service.ErrNotConfigured)
		return "", false
	}
	return s.currentUser(request, response)
}

func (s *Server) listInvitations(request *restful.Request, response *restful.Response) {
	actor, ok := s.invitationActor(request, response)
	if !ok {
		return
	}
	limit, offset, err := parsePageQuery(request, 20, 100)
	if err != nil {
		s.writeError(response, err)
		return
	}
	values, err := s.Invitations.ListInvitations(request.Request.Context(), actor, limit, offset)
	if err != nil {
		s.writeError(response, err)
		return
	}
	if values == nil {
		values = []repository.InvitationView{}
	}
	_ = response.WriteEntity(values)
}

func (s *Server) createInvitation(request *restful.Request, response *restful.Response) {
	actor, ok := s.invitationActor(request, response)
	if !ok || !s.allowPasswordAttempt(request, response, "invitation-send:"+actor) {
		return
	}
	var body service.CreateInvitationInput
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, service.ErrValidation)
		return
	}
	value, err := s.Invitations.CreateInvitation(request.Request.Context(), actor, body)
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteHeaderAndEntity(http.StatusCreated, value)
}

func (s *Server) resendInvitation(request *restful.Request, response *restful.Response) {
	actor, ok := s.invitationActor(request, response)
	if !ok || !s.allowPasswordAttempt(request, response, "invitation-send:"+actor) {
		return
	}
	value, err := s.Invitations.ResendInvitation(request.Request.Context(), actor, request.PathParameter("invitation_id"))
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteHeaderAndEntity(http.StatusCreated, value)
}

func (s *Server) revokeInvitation(request *restful.Request, response *restful.Response) {
	actor, ok := s.invitationActor(request, response)
	if !ok {
		return
	}
	if err := s.Invitations.RevokeInvitation(request.Request.Context(), actor, request.PathParameter("invitation_id")); err != nil {
		s.writeError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (s *Server) previewInvitation(request *restful.Request, response *restful.Response) {
	if s.Invitations == nil {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	if !s.allowPasswordAttempt(request, response, "invitation-preview:"+transportAddress(request.Request)) {
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, service.ErrInvitationUnavailable)
		return
	}
	value, err := s.Invitations.PreviewInvitation(request.Request.Context(), body.Token)
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(value)
}

func (s *Server) acceptInvitation(request *restful.Request, response *restful.Response) {
	if s.Invitations == nil || s.SessionSigner == nil {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	if !s.allowPasswordAttempt(request, response, "invitation-accept:"+transportAddress(request.Request)) {
		return
	}
	var body struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, service.ErrInvitationUnavailable)
		return
	}
	user, err := s.Invitations.AcceptInvitation(request.Request.Context(), body.Token, body.Password)
	if err != nil {
		s.writeError(response, err)
		return
	}
	s.finishPrimaryLogin(request, response, user, false)
}
