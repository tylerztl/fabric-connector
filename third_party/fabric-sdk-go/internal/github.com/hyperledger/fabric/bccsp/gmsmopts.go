package bccsp

// GMSM2KeyGenOpts contains options for GMSM2 key generation.
type GMSM2KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *GMSM2KeyGenOpts) Algorithm() string {
	return GMSM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *GMSM2KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// GMSM2PrivateKeyImportOpts contains options for GMSM2 private key importation in DER format
// or PKCS#8 format.
type GMSM2PrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *GMSM2PrivateKeyImportOpts) Algorithm() string {
	return GMSM2
}

// Ephemeral returns true if the key generated has to be ephemeral,
// false otherwise.
func (opts *GMSM2PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// GMSM2PrivateKeyImportOpts contains options for GMSM2 private key importation in DER format
// or PKCS#8 format.
type GMSM2PublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *GMSM2PublicKeyImportOpts) Algorithm() string {
	return GMSM2
}

// Ephemeral returns true if the key generated has to be ephemeral,
// false otherwise.
func (opts *GMSM2PublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// GMSM4KeyGenOpts contains options for SM4 key generation at 128 security level
type GMSM4KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *GMSM4KeyGenOpts) Algorithm() string {
	return GMSM4
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *GMSM4KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// GMSM4ImportKeyOpts contains options for GMSM4 secret key importation in DER format
// or PKCS#8 format.
type GMSM4ImportKeyOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *GMSM4ImportKeyOpts) Algorithm() string {
	return GMSM4
}

// Ephemeral returns true if the key generated has to be ephemeral,
// false otherwise.
func (opts *GMSM4ImportKeyOpts) Ephemeral() bool {
	return opts.Temporary
}
