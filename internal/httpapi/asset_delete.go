package httpapi

import (
	"net/http"

	"github.com/emicklei/go-restful/v3"
)

func (s *Server) deleteAsset(request *restful.Request, response *restful.Response) {
	actor, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	if err := s.Service.DeleteAsset(request.Request.Context(), actor, request.PathParameter("asset_id")); err != nil {
		s.writeError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}
