// Code generated by go-swagger; DO NOT EDIT.

package engines

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/ory/keto/internal/httpclient/models"
)

// ListOryAccessControlPolicyRolesReader is a Reader for the ListOryAccessControlPolicyRoles structure.
type ListOryAccessControlPolicyRolesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListOryAccessControlPolicyRolesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListOryAccessControlPolicyRolesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 500:
		result := NewListOryAccessControlPolicyRolesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewListOryAccessControlPolicyRolesOK creates a ListOryAccessControlPolicyRolesOK with default headers values
func NewListOryAccessControlPolicyRolesOK() *ListOryAccessControlPolicyRolesOK {
	return &ListOryAccessControlPolicyRolesOK{}
}

/*ListOryAccessControlPolicyRolesOK handles this case with default header values.

Roles is an array of roles.
*/
type ListOryAccessControlPolicyRolesOK struct {
	Payload []*models.OryAccessControlPolicyRole
}

func (o *ListOryAccessControlPolicyRolesOK) Error() string {
	return fmt.Sprintf("[GET /engines/acp/ory/{flavor}/roles][%d] listOryAccessControlPolicyRolesOK  %+v", 200, o.Payload)
}

func (o *ListOryAccessControlPolicyRolesOK) GetPayload() []*models.OryAccessControlPolicyRole {
	return o.Payload
}

func (o *ListOryAccessControlPolicyRolesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListOryAccessControlPolicyRolesInternalServerError creates a ListOryAccessControlPolicyRolesInternalServerError with default headers values
func NewListOryAccessControlPolicyRolesInternalServerError() *ListOryAccessControlPolicyRolesInternalServerError {
	return &ListOryAccessControlPolicyRolesInternalServerError{}
}

/*ListOryAccessControlPolicyRolesInternalServerError handles this case with default header values.

The standard error format
*/
type ListOryAccessControlPolicyRolesInternalServerError struct {
	Payload *ListOryAccessControlPolicyRolesInternalServerErrorBody
}

func (o *ListOryAccessControlPolicyRolesInternalServerError) Error() string {
	return fmt.Sprintf("[GET /engines/acp/ory/{flavor}/roles][%d] listOryAccessControlPolicyRolesInternalServerError  %+v", 500, o.Payload)
}

func (o *ListOryAccessControlPolicyRolesInternalServerError) GetPayload() *ListOryAccessControlPolicyRolesInternalServerErrorBody {
	return o.Payload
}

func (o *ListOryAccessControlPolicyRolesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(ListOryAccessControlPolicyRolesInternalServerErrorBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*ListOryAccessControlPolicyRolesInternalServerErrorBody list ory access control policy roles internal server error body
swagger:model ListOryAccessControlPolicyRolesInternalServerErrorBody
*/
type ListOryAccessControlPolicyRolesInternalServerErrorBody struct {

	// code
	Code int64 `json:"code,omitempty"`

	// details
	Details []interface{} `json:"details"`

	// message
	Message string `json:"message,omitempty"`

	// reason
	Reason string `json:"reason,omitempty"`

	// request
	Request string `json:"request,omitempty"`

	// status
	Status string `json:"status,omitempty"`
}

// Validate validates this list ory access control policy roles internal server error body
func (o *ListOryAccessControlPolicyRolesInternalServerErrorBody) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *ListOryAccessControlPolicyRolesInternalServerErrorBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *ListOryAccessControlPolicyRolesInternalServerErrorBody) UnmarshalBinary(b []byte) error {
	var res ListOryAccessControlPolicyRolesInternalServerErrorBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
