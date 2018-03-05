## sandbox

### example

```
{
	"no_win32k": false,
	"force_reloc": false,
	"critical_heap": false,
	"bottom_up_aslr": false,
	"high_entropy_aslr": true,
	"critical_handle": true,
	"no_ep": true,
	"no_dyncode": true,
	"no_fontload": true,
	"no_remote_img": true,
	"no_low_img": true,
	"sysimg_prefer": true,
	"dep": true,
	"sehop": true,
	"no_child": true,

	"restrict_ui": false,
	"timeout": 500000000,
	"memory": 41943040,
    "active_process": 1,

	"user": "",
	"password": "",
    "integrity_level": "mid",

	"restricted_token": true,
	"remove_all_priv": true,
	"remove_privs": [
	],
	"deny_sids": [
	],
	"restrict_sids": [
	],

	"redir_io": false,
	"wait_time": -1
}

```
