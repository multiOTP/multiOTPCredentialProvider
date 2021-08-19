#pragma once

// The indexes of each of the fields in our credential provider's appended tiles.
enum FIELD_ID
{
	FID_LOGO = 0,
	FID_LARGE_TEXT = 1,
	FID_SMALL_TEXT = 2,
	FID_USERNAME = 3,
	FID_LDAP_PASS = 4,
	FID_OTP = 5,
	FID_NEW_PASS_1 = 6,
	FID_NEW_PASS_2 = 7,
	FID_SUBMIT_BUTTON = 8,
	FID_SUBTEXT = 9,
	FID_REQUIRE_SMS = 10,
	FID_NUM_FIELDS = 11,
};

// The first value indicates when the tile is displayed (selected, not selected)
// the second indicates things like whether the field is enabled, whether it has key focus, etc.
struct FIELD_STATE_PAIR
{
	// Source : https://docs.microsoft.com/en-us/windows/win32/api/credentialprovider/ne-credentialprovider-credential_provider_field_state
	CREDENTIAL_PROVIDER_FIELD_STATE cpfs; // Alowed values CPFS_HIDDEN,	CPFS_DISPLAY_IN_SELECTED_TILE, CPFS_DISPLAY_IN_DESELECTED_TILE,	CPFS_DISPLAY_IN_BOTH
	CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis; // Allowed values : CPFIS_NONE, CPFIS_READONLY, CPFIS_DISABLED, CPFIS_FOCUSED
};

// These two arrays are seperate because a credential provider might
// want to set up a credential with various combinations of field state pairs 
// and field descriptors.

// The field state value indicates whether the field is displayed
// in the selected tile, the deselected tile, or both.
// The Field interactive state indicates when 
static const FIELD_STATE_PAIR s_rgScenarioDisplayAllFields[] =
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// FID_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// FID_LARGE_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_SMALL_TEXT
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// FID_USERNAME
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_LDAP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_OTP
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_NEW_PASS_1
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_NEW_PASS_1
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_SUBMIT_BUTTON
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_SUBTEXT
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE},           // FID_REQUIRE_SMS
};

static const FIELD_STATE_PAIR s_rgScenarioUnlockPasswordOTP[] =
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// FID_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// FID_LARGE_TEXT
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// FID_SMALL_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_USERNAME
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// FID_LDAP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_OTP
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_NEW_PASS_1
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_NEW_PASS_1
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_SUBMIT_BUTTON
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_SUBTEXT
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE},           // FID_REQUIRE_SMS
};

static const FIELD_STATE_PAIR s_rgScenarioSecondStepOTP[] =
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// FID_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// FID_LARGE_TEXT
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_SMALL_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_USERNAME
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_LDAP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// FID_OTP
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_NEW_PASS_1
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_NEW_PASS_1
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_SUBMIT_BUTTON
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_SUBTEXT
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE},           // FID_REQUIRE_SMS
};

static const FIELD_STATE_PAIR s_rgScenarioLogonFirstStepUserLDAP[] =
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// FID_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// FID_LARGE_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_SMALL_TEXT
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// FID_USERNAME
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_LDAP_PASS
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_OTP
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_NEW_PASS_1
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_NEW_PASS_1
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_SUBMIT_BUTTON
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_SUBTEXT
	{ CPFS_HIDDEN, CPFIS_NONE},                             // FID_REQUIRE_SMS
};

// Show all 3 fields for password change
static const FIELD_STATE_PAIR s_rgScenarioPasswordChange[] =
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// FID_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// FID_LARGE_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_SMALL_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_USERNAME
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_LDAP_PASS
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_OTP
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// FID_NEW_PASS_1
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_NEW_PASS_1
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_SUBMIT_BUTTON
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_SUBTEXT
	{ CPFS_HIDDEN, CPFIS_NONE},                             // FID_REQUIRE_SMS
};

static const FIELD_STATE_PAIR s_rgScenarioUnlockFirstStepPassword[] =
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// FID_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// FID_LARGE_TEXT
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// FID_SMALL_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_USERNAME
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// FID_LDAP_PASS
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_OTP
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_NEW_PASS_1
	{ CPFS_HIDDEN, CPFIS_NONE },							// FID_NEW_PASS_1
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_SUBMIT_BUTTON
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// FID_SUBTEXT
	{ CPFS_HIDDEN, CPFIS_NONE },                            // FID_REQUIRE_SMS
};

// Field descriptors for unlock and logon.
// The first field is the index of the field.
// The second is the type of the field.
// The third is the name of the field, NOT the value which will appear in the field.
static CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgScenarioCredProvFieldDescriptors[] =
{
	{ FID_LOGO, CPFT_TILE_IMAGE, L"privacyIDEA Login" },
	{ FID_LARGE_TEXT, CPFT_LARGE_TEXT, L"LargeText" },
	{ FID_SMALL_TEXT, CPFT_SMALL_TEXT, L"SmallText" },
	{ FID_USERNAME, CPFT_EDIT_TEXT, L"Username" },
	{ FID_LDAP_PASS, CPFT_PASSWORD_TEXT, L"Password" },
	{ FID_OTP, CPFT_PASSWORD_TEXT, L"One-Time Password" },
	{ FID_NEW_PASS_1, CPFT_PASSWORD_TEXT, L"New Password" },
	{ FID_NEW_PASS_2, CPFT_PASSWORD_TEXT, L"Confirm password" },
	{ FID_SUBMIT_BUTTON, CPFT_SUBMIT_BUTTON, L"Submit" },
	{ FID_SUBTEXT, CPFT_SMALL_TEXT, L"Sign in to: "},
	{ FID_REQUIRE_SMS, CPFT_COMMAND_LINK,  L"Receive an OTP by SMS"},
};