// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// OryAccessControlPolicyAllowedInput Input for checking if a request is allowed or not.
//
// swagger:model oryAccessControlPolicyAllowedInput
type OryAccessControlPolicyAllowedInput struct {

	// Action is the action that is requested on the resource.
	Action string `json:"action,omitempty"`

	// Context is the request's environmental context.
	Context interface{} `json:"context,omitempty"`

	// Resource is the resource that access is requested to.
	Resource string `json:"resource,omitempty"`

	// Subject is the subject that is requesting access.
	Subject string `json:"subject,omitempty"`
}

// Validate validates this ory access control policy allowed input
func (m *OryAccessControlPolicyAllowedInput) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OryAccessControlPolicyAllowedInput) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OryAccessControlPolicyAllowedInput) UnmarshalBinary(b []byte) error {
	var res OryAccessControlPolicyAllowedInput
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
