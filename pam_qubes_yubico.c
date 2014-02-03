/* Written by Simon Josefsson <simon@yubico.com>.
 * Copyright (c) 2006-2013 Yubico AB
 * Copyright (c) 2011 Tollef Fog Heen <tfheen@err.no>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "util.h"
#include "yubikey.h"

/* Libtool defines PIC for shared objects */
#ifndef PIC
#define PAM_STATIC
#endif

/* These #defines must be present according to PAM documentation. */
#define PAM_SM_AUTH

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#ifndef PAM_EXTERN
#ifdef PAM_STATIC
#define PAM_EXTERN static
#else
#define PAM_EXTERN extern
#endif
#endif

#define TOKEN_OTP_LEN 32
#define AES_KEY_LEN 32

enum key_mode {
  LOCAL_CLIENT
};

struct cfg
{
  char *client_key;
  char *client_pwd;
  int debug;
  int alwaysok;
  int verbose_otp;
  int try_first_pass;
  int use_first_pass;
  enum key_mode mode;
  char *last_login_path;
  char *otp_path;
};

#ifdef DBG
#undef DBG
#endif
#define DBG(x) if (cfg->debug) { D(x); }

static int
is_password_valid(const char *provided, const char *reference) {
  int password_valid = 0;

  /* Password required? */
  if (reference == NULL)
    if (provided == NULL)
      password_valid = 1;
    else
      return password_valid;
  else if (provided != NULL)
    if (strcmp(provided, reference) == 0)
      password_valid = 1;
  return password_valid;
}

static int
display_error(pam_handle_t *pamh, const char *message) {
  struct pam_conv *conv;
  const struct pam_message *pmsg[1];
  struct pam_message msg[1];
  struct pam_response *resp = NULL;
  int retval;

  retval = pam_get_item (pamh, PAM_CONV, (const void **) &conv);
  if (retval != PAM_SUCCESS) {
    D(("get conv returned error: %s", pam_strerror (pamh, retval)));
    return retval;
  }

  pmsg[0] = &msg[0];
  msg[0].msg = message;
  msg[0].msg_style = PAM_ERROR_MSG;
  retval = conv->conv(1, pmsg, &resp, conv->appdata_ptr);

  if (retval != PAM_SUCCESS) {
    D(("conv returned error: %s", pam_strerror (pamh, retval)));
    return retval;
  }

  D(("conv returned: '%s'", resp->resp));
  return retval;
}

static int
is_yubikey_otp_valid(pam_handle_t *pamh, const char *aeskey, const char *last_login_path, const char *otp_path) {
  int otp_valid = 0;
  const char *errstr = NULL;
  int fd;
  struct stat st;
  FILE *f = NULL;
  char previous_token[TOKEN_OTP_LEN + 1];
  char token[TOKEN_OTP_LEN + 1];
  uint8_t is_compromised = 0;
  uint8_t was_compromised = 1;
  int r;
  uint8_t key[TOKEN_OTP_LEN];
  yubikey_token_st tok;
  int previous_counter = -1;
  int counter = -1;

  /* validating aeskey length*/
  if ((aeskey == NULL) || (strlen (aeskey) != 32)) {
    D(("aeskey configured is of the WRONG length."));
    errstr = "error: Invalid PAM Module configuration. A 32 characters Hex encoded AES-key must be provided.\n";
    goto otp_validated;
  }

  /* getting last otp login information */
  fd = open(last_login_path, O_RDONLY, 0);
  if (fd < 0) {
    D(("Cannot open file: %s (%s)", last_login_path, strerror(errno)));
    errstr = "error: Unable to open last login file.\n";
    goto otp_validated;
  }

  if (fstat(fd, &st) < 0) {
    D(("Cannot stat file: %s (%s)", last_login_path, strerror(errno)));
    close(fd);
    errstr = "error: Unable to stat last login file.\n";
    goto otp_validated;
  }

  if (!S_ISREG(st.st_mode)) {
    D(("%s is not a regular file", last_login_path));
    close(fd);
    errstr = "error: Last login file is not a regular file.\n";
    goto otp_validated;
  }

  f = fdopen(fd, "r");
  if (f == NULL) {
    D(("fdopen: %s", strerror(errno)));
    close(fd);
    errstr = "fdopen error.";
    goto otp_validated;
  }

  r = fscanf(f, "%d:%32[a-z]:%d", &was_compromised, previous_token, &previous_counter);
  D(("Last login: Was compromised:%d", was_compromised));
  D(("Last Login: Previous Token:%s", previous_token));
  D(("Last Login: Previous Counter:%d", previous_counter));

  if (fclose(f) < 0) {
    f = NULL;
    D(("fclose: %s", strerror(errno)));
    errstr = "fclose errors.";
    goto otp_validated;
  }

  f = NULL;

  if (was_compromised != 0) {
    D(("Authentication method cannot be trusted anymore due to suspiscious activity during last login."));
    goto otp_validated;
  }

  /* getting and validating OTP */
  fd = open(otp_path, O_RDONLY, 0);
  if (fd < 0) {
    D(("Cannot open file: %s (%s)", otp_path, strerror(errno)));
    errstr = "error: Unable to open OTP file.\n";
    goto otp_validated;
  }

  if (fstat(fd, &st) < 0) {
    D(("Cannot stat file: %s (%s)", otp_path, strerror(errno)));
    close(fd);
    errstr = "error: Unable to stat OTP file.\n";
    goto otp_validated;
  }

  if (!S_ISREG(st.st_mode)) {
    D(("%s is not a regular file", otp_path));
    close(fd);
    errstr = "error: OTP file is not a regular file.\n";
    goto otp_validated;
  }

  f = fdopen(fd, "r");
  if (f == NULL) {
    D(("fdopen: %s", strerror(errno)));
    close(fd);
    errstr = "fdopen error.";
    goto otp_validated;
  }

  r = fscanf(f, "%32[a-z]", token);
  if(r == 1) {
    D(("Token=%s", token));
    yubikey_modhex_decode ((char *) key, token, TOKEN_OTP_LEN);
    D(("Key=%s", key));
    D(("AESKey=%s", aeskey));
    yubikey_hex_decode ((char *) key, aeskey, TOKEN_OTP_LEN);
    D(("Key=%s", key));
    yubikey_parse ((uint8_t *) token, key, &tok);

    /* is the CRC OK? */
    if (!yubikey_crc_ok_p ((uint8_t *) & tok))
    {
      D(("crc NOT OK"));
      is_compromised = 1;
      goto otp_validated;
    }
    D(("CRC OK"));

    /* Has this OTP been the first OTP generated after key insertion */
    if (tok.use != 0) {
      D(("Not a power up OTP"));
      is_compromised = 1;
      goto otp_validated;
    }
    D(("Session use: %d (0x%02x)\n", tok.use, tok.use));

    /* Has the OTP been replayed? */
    counter = yubikey_counter (tok.ctr);
    D(("Yubikey counter: %d",counter));

    if (previous_counter + 1 > counter) {
      D(("Replayed token. Counter is lower than expected value."));
      is_compromised = 1;
      goto otp_validated; 
    }

    /* Is the OTP the next consecutive OTP? */
    if (previous_counter + 1 < counter) {
        D(("A token was lost. Counter is higher than expected value."));
        is_compromised = 1;
        goto otp_validated;
    }
    D(("counter: %d (0x%04x)\n", counter, counter));
    D(("timestamp (low): %d (0x%04x)\n", tok.tstpl, tok.tstpl));
    D(("timestamp (high): %d (0x%02x)\n", tok.tstph, tok.tstph));
    D(("random: %d (0x%02x)\n", tok.rnd, tok.rnd));
    D(("crc: %d (0x%04x)\n", tok.crc, tok.crc));
    otp_valid = 1;
  }
  if (fclose(f) < 0) {
    f = NULL;
    goto otp_validated;
  }
  f = NULL;
  otp_validated:

  /* Need to write to last_login compromised:token:counter if compromised was not already == 1 */
  if (was_compromised == 0) {
    fd = open(last_login_path, O_WRONLY, 0);
    if (fd < 0) {
      D(("Cannot open file: %s (%s)", last_login_path, strerror(errno)));
      errstr = "error: Unable to open for write last login file.\n";
      goto out;
    }

    if (fstat(fd, &st) < 0) {
      D(("Cannot stat file: %s (%s)", last_login_path, strerror(errno)));
      close(fd);
      errstr = "error: Unable to stat last login file.\n";
      goto out;
    }

    if (!S_ISREG(st.st_mode)) {
      D(("%s is not a regular file", last_login_path));
      close(fd);
      errstr = "error: Last login file is not a regular file.\n";
      goto out;
    }

    f = fdopen(fd, "w");
    if (f == NULL) {
      D(("fdopen: %s", strerror(errno)));
      close(fd);
      errstr = "fdopen error.";
      goto out;
    } else {
      D(("Last login file is all OK."));
      rewind(f);
      fd = fileno(f);
      if (fd == -1)
        goto out;

     // if (ftruncate(fd, 0))
       // goto out;
      if (is_compromised != 0) {
        D(("Saving that the authentication method just got compromised."));
        fprintf(f, "%d", is_compromised);
      } else {
	D(("Saving the last OTP and counter down."));
        fprintf(f, "%d:%s:%d", is_compromised, token, counter);
      }

      if (fflush(f) < 0)
        goto out;

      if (fsync(fd) < 0)
        goto out;
    }
  } else {
    D(("Not saving last_login, already compromised."));
  }
  out:
  if (errstr)
    display_error(pamh, errstr); 
  D(("Final OTP validation returned=%d", otp_valid));
  return otp_valid;
}  

static void
parse_cfg (int flags, int argc, const char **argv, struct cfg *cfg)
{
  int i;

  memset (cfg, 0, sizeof(struct cfg));
  cfg->mode = LOCAL_CLIENT;

  for (i = 0; i < argc; i++)
    {
      if (strncmp (argv[i], "aeskey=", 7) == 0)
	cfg->client_key = (char *) argv[i] + 7;
      if (strncmp (argv[i], "pwd=", 4) == 0)
        cfg->client_pwd = (char *) argv[i] +4;
      if (strcmp (argv[i], "debug") == 0)
	cfg->debug = 1;
      if (strcmp (argv[i], "alwaysok") == 0)
	cfg->alwaysok = 1;
      if (strcmp (argv[i], "verbose_otp") == 0)
	cfg->verbose_otp = 1;
      if (strncmp (argv[i], "last_login_path=", 16) == 0)
        cfg->last_login_path = (char *) argv[i] + 16;
      else
        cfg->last_login_path = "/var/yubikey/last_login";
      if (strncmp (argv[i], "otp_path=", 9) == 0)
        cfg->otp_path = (char *) argv[i] + 9;
      else
        cfg->otp_path = "/var/yubikey/yubikey.otp";
      if (strcmp (argv[i], "try_first_pass") == 0)
	cfg->try_first_pass = 1;
      if (strcmp (argv[i], "use_first_pass") == 0)
	cfg->use_first_pass = 1;
    }

  if (cfg->debug)
    {
      D (("called."));
      D (("flags %d argc %d", flags, argc));
      for (i = 0; i < argc; i++)
	D (("argv[%d]=%s", i, argv[i]));
      D (("aeskey=%s", cfg->client_key ? cfg->client_key : "(null)"));
      D(("pwd=%s", cfg->client_pwd ? cfg->client_pwd : "(null)"));
      D (("debug=%d", cfg->debug));
      D (("alwaysok=%d", cfg->alwaysok));
      D (("verbose_otp=%d", cfg->verbose_otp));
      D (("last_login_path=%s", cfg->last_login_path ? cfg->last_login_path :"(null)"));
      D (("otp_path=%s", cfg->otp_path ? cfg->otp_path :"(null)"));
      D (("try_first_pass=%d", cfg->try_first_pass));
      D (("use_first_pass=%d", cfg->use_first_pass));
    }
}

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t * pamh,
		     int flags, int argc, const char **argv)
{
  int retval, rc;
  const char *user = NULL;
  const char *password = NULL;
  char otp[TOKEN_OTP_LEN + 1] = { 0 };
  int password_len = 0;
  int skip_bytes = 0;
  int valid_token = 0;
  struct pam_conv *conv;
  const struct pam_message *pmsg[1];
  struct pam_message msg[1];
  struct pam_response *resp;
  int nargs = 1;
  struct cfg cfg_st;
  struct cfg *cfg = &cfg_st; /* for DBG macro */

  parse_cfg (flags, argc, argv, cfg);

  retval = pam_get_user (pamh, &user, NULL);
  if (retval != PAM_SUCCESS)
    {
      DBG (("get user returned error: %s", pam_strerror (pamh, retval)));
      goto done;
    }

  if (cfg->try_first_pass || cfg->use_first_pass)
    {
      retval = pam_get_item (pamh, PAM_AUTHTOK, (const void **) &password);
      if (retval != PAM_SUCCESS)
	{
	  DBG (("get password returned error: %s",
	      pam_strerror (pamh, retval)));
	  goto done;
	}
      DBG (("get password returned: %s", password));
    }

  if (cfg->use_first_pass && password == NULL)
    {
      DBG (("use_first_pass set and no password, giving up"));
      retval = PAM_AUTH_ERR;
      goto done;
    }

  if (password == NULL)
    {
      retval = pam_get_item (pamh, PAM_CONV, (const void **) &conv);
      if (retval != PAM_SUCCESS)
	{
          DBG (("get conv returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}

      pmsg[0] = &msg[0];
      {
#define QUERY_TEMPLATE "Yubikey for `%s': "
	size_t len = strlen (QUERY_TEMPLATE) + strlen (user);
	int wrote;

	msg[0].msg = malloc (len);
	if (!msg[0].msg)
	  {
	    retval = PAM_BUF_ERR;
	    goto done;
	  }

	wrote = snprintf ((char *) msg[0].msg, len, QUERY_TEMPLATE, user);
	if (wrote < 0 || wrote >= len)
	  {
	    retval = PAM_BUF_ERR;
	    goto done;
	  }
      }
      msg[0].msg_style = cfg->verbose_otp ? PAM_PROMPT_ECHO_ON : PAM_PROMPT_ECHO_OFF;
      resp = NULL;

      retval = conv->conv (nargs, pmsg, &resp, conv->appdata_ptr);

      free ((char *) msg[0].msg);

      if (retval != PAM_SUCCESS)
	{
	  DBG (("conv returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}

      if (resp->resp == NULL)
	{
	  DBG (("conv returned NULL passwd?"));
	  retval = PAM_AUTH_ERR;
	  goto done;
	}

      DBG (("conv returned %lu bytes", (unsigned long) strlen(resp->resp)));

      password = resp->resp;
    }

  password_len = strlen (password);
    if (password_len > 0)
    {
      char *onlypasswd = strdup (password);

      if (! onlypasswd) {
	retval = PAM_BUF_ERR;
	goto done;
      }

      DBG (("Extracted a probable system password - "
	    "setting item PAM_AUTHTOK"));

      retval = pam_set_item (pamh, PAM_AUTHTOK, onlypasswd);
      free (onlypasswd);
      if (retval != PAM_SUCCESS)
	{
	  DBG (("set_item returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}
    }
  else
    password = NULL;

    /* compare passwords */
    if ((is_password_valid(password, cfg->client_pwd) != 0) && (is_yubikey_otp_valid(pamh, cfg->client_key, cfg->last_login_path, cfg->otp_path) != 0))
      {
        retval = PAM_SUCCESS;
        goto done;
      }
    else
      {
        retval = PAM_AUTH_ERR;
        goto done;
      }

/* never called ???*/
  valid_token = -1;
  switch(valid_token)
    {
    case 1:
      retval = PAM_SUCCESS;
      break;
    case 0:
      DBG (("Internal error while validating user"));
      retval = PAM_AUTHINFO_UNAVAIL;
      break;
    case -1:
      DBG (("Unauthorized token for this user"));
      retval = PAM_AUTH_ERR;
      break;
    case -2:
      DBG (("Unknown user"));
      retval = PAM_USER_UNKNOWN;
      break;
    default:
      DBG (("Unhandled value for token-user validation"));
      retval = PAM_AUTHINFO_UNAVAIL;
    }

done:
  if (cfg->alwaysok && retval != PAM_SUCCESS)
    {
      DBG (("alwaysok needed (otherwise return with %d)", retval));
      retval = PAM_SUCCESS;
    }
  DBG (("done. [%s]", pam_strerror (pamh, retval)));
  pam_set_data (pamh, "yubico_setcred_return", (void*) (intptr_t) retval, NULL);

  return retval;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

#ifdef PAM_STATIC

struct pam_module _pam_qubes_yubico_modstruct = {
  "pam_qubes_yubico",
  pam_sm_authenticate,
  pam_sm_setcred,
  NULL,
  NULL,
  NULL,
  NULL
};

#endif
