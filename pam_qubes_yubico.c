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
//#include <stdarg.h>
//#include <ctype.h>
//#include <syslog.h>

//#include <sys/types.h>
//#include <sys/stat.h>
#include <fcntl.h>
//#include <unistd.h>
#include <errno.h>
#include <string.h>
//#include <pwd.h>

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

  /* validating aeskey */
  if ((aeskey == NULL) || (strlen (aeskey) != 32)) {
    D(("aeskey configured is of the WRONG length."));
    errstr = "error: Invalid PAM Module configuration. A 32 characters Hex encoded AES-key must be provided.\n";
    goto otp_validated;
  } else {
    D(("aeskey configured is of the right length."));
  }

  /* getting last otp login information */
  fd = open(last_login_path, O_RDONLY, 0);
  if (fd < 0) {
    D(("Cannot open file: %s (%s)", last_login_path, strerror(errno)));
    errstr = "error: Unable to open last login file.\n";
    goto otp_validated;
  } else {
    D(("Last login file opened."));
  }

  if (fstat(fd, &st) < 0) {
    D(("Cannot stat file: %s (%s)", last_login_path, strerror(errno)));
    close(fd);
    errstr = "error: Unable to stat last login file.\n";
    goto otp_validated;
  } else {
    D(("Last login file stated."));
  }

  if (!S_ISREG(st.st_mode)) {
    D(("%s is not a regular file", last_login_path));
    close(fd);
    errstr = "error: Last login file is not a regular file.\n";
    goto otp_validated;
  } else {
    D(("Last login file is a regular file."));
  }

  f = fdopen(fd, "r");
  if (f == NULL) {
    D(("fdopen: %s", strerror(errno)));
    close(fd);
    errstr = "fdopen error.";
    goto otp_validated;
  } else {
    D(("Last login file is all OK."));
  }
  r = fscanf(f, "%d:%32[a-z]:%d", &was_compromised, previous_token, &previous_counter);
  D(("Last login value read: Was compromised:%d", was_compromised));
  D(("Last Login value read: Previous Token:%s", previous_token));
  D(("Last Login valur read: Previous Counter:%d", previous_counter));

  if (fclose(f) < 0) {
    f = NULL;
    D(("fclose: %s", strerror(errno)));
    errstr = "fclose errors.";
    goto otp_validated;
  }

  f = NULL;
  if (was_compromised != 0) {
    D(("Authentication method cannot be trusted due to suspiscious activity during last login."));
    goto otp_validated;
  }

  /* getting and validating OTP */
  fd = open(otp_path, O_RDONLY, 0);
  if (fd < 0) {
    D(("Cannot open file: %s (%s)", otp_path, strerror(errno)));
    errstr = "error: Unable to open OTP file.\n";
    goto otp_validated;
  } else {
    D(("OTP file opened."));
  }

  if (fstat(fd, &st) < 0) {
    D(("Cannot stat file: %s (%s)", otp_path, strerror(errno)));
    close(fd);
    errstr = "error: Unable to stat OTP file.\n";
    goto otp_validated;
  } else {
    D(("OPT file stated."));
  }

  if (!S_ISREG(st.st_mode)) {
    D(("%s is not a regular file", otp_path));
    close(fd);
    errstr = "error: OTP file is not a regular file.\n";
    goto otp_validated;
  } else {
    D(("OTP file is a regular file."));
  }

  f = fdopen(fd, "r");
  if (f == NULL) {
    D(("fdopen: %s", strerror(errno)));
    close(fd);
    errstr = "fdopen error.";
    goto otp_validated;
  } else {
    D(("OTP file is all OK."));
  }

  r = fscanf(f, "%32[a-z]", token);
  if(r == 1) {
    D(("Token=%s", token));
    yubikey_modhex_decode ((char *) key, token, TOKEN_OTP_LEN);
    D(("Key=%s", &key));
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

    /* Has this OTP been the first OTP generated after key insertion */
    if (tok.use != 0) {
      D(("Not a power up OTP"));
      is_compromised = 1;
      goto otp_validated;
    }
    D(("CRC OK"));
    D(("Session use: %d (0x%02x)\n", tok.use, tok.use));
    counter = yubikey_counter (tok.ctr);
    D(("Yubikey counter: %d",counter));

    /* Has the OTP been replayed? */
    if (previous_counter + 1 > counter) {
      D(("Replayed token"));
      is_compromised = 1;
      goto otp_validated; 
    }

    /* Is the OTP the next consecutive OTP? */
    if (previous_counter + 1 < counter) {
        D(("A token was lost"));
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
      goto otp_validated;
    } else {
      D(("Last login file opened for write."));
    }

    if (fstat(fd, &st) < 0) {
      D(("Cannot stat file: %s (%s)", last_login_path, strerror(errno)));
      close(fd);
      errstr = "error: Unable to stat last login file.\n";
      goto otp_validated;
    } else {
      D(("OPT file stated."));
    }

    if (!S_ISREG(st.st_mode)) {
      D(("%s is not a regular file", last_login_path));
      close(fd);
      errstr = "error: Last login file is not a regular file.\n";
      goto otp_validated;
    } else {
      D(("Last login file is a regular file."));
    }

    f = fdopen(fd, "w");
    if (f == NULL) {
      D(("fdopen: %s", strerror(errno)));
      close(fd);
      errstr = "fdopen error.";
      goto otp_validated;
    } else {
      D(("Last login file is all OK."));
      rewind(f);
      fd = fileno(f);
      if (fd == -1)
        goto out;

     // if (ftruncate(fd, 0))
       // goto out;
      if (is_compromised != 0) {
        D(("Writing that the authentication method just got compromised."));
        fprintf(f, "%d", is_compromised);
      } else {
	D(("Writting the last OTP and counter down."));
        fprintf(f, "%d:%s:%d", is_compromised, token, counter);
      }

      if (fflush(f) < 0)
        goto out;

      if (fsync(fd) < 0)
        goto out;
    }
  } else {
    D(("Not modifying last_login as already compromised."));
  }
  out:
  if (errstr)
    display_error(pamh, errstr); 
  D(("Final OTP validation returned=%d", otp_valid));
  return otp_valid;
}  
//#if HAVE_CR
//static int
//do_challenge_response(pam_handle_t *pamh, struct cfg *cfg, const char *username)
//{
//  char *userfile = NULL, *tmpfile = NULL;
//  FILE *f = NULL;
//  char buf[CR_RESPONSE_SIZE + 16], response_hex[CR_RESPONSE_SIZE * 2 + 1];
//  int ret, fd;

//  unsigned int response_len = 0;
//  YK_KEY *yk = NULL;
//  CR_STATE state;

//  const char *errstr = NULL;

//  struct passwd *p;
//  struct stat st;

  /* we must declare two sepparate privs structures as they can't be reused */
//  PAM_MODUTIL_DEF_PRIVS(privs);
//  PAM_MODUTIL_DEF_PRIVS(privs2);

//  ret = PAM_AUTH_ERR;

//  if (! init_yubikey(&yk)) {
//    DBG(("Failed initializing YubiKey"));
//    goto out;
//  }

//  if (! check_firmware_version(yk, false, true)) {
//    DBG(("YubiKey does not support Challenge-Response (version 2.2 required)"));
//    goto out;
//  }


//  if (! get_user_challenge_file (yk, cfg->chalresp_path, username, &userfile)) {
//    DBG(("Failed getting user challenge file for user %s", username));
//    goto out;
//  }

//  DBG(("Loading challenge from file %s", userfile));

//  p = getpwnam (username);
//  if (p == NULL) {
//      DBG (("getpwnam: %s", strerror(errno)));
//      goto out;
//  }

  /* Drop privileges before opening user file. */
//  if (pam_modutil_drop_priv(pamh, &privs, p)) {
//      DBG (("could not drop privileges"));
//      goto out;
//  }

//  fd = open(userfile, O_RDONLY, 0);
//  if (fd < 0) {
//      DBG (("Cannot open file: %s (%s)", userfile, strerror(errno)));
//      goto restpriv_out;
//  }

//  if (fstat(fd, &st) < 0) {
//      DBG (("Cannot stat file: %s (%s)", userfile, strerror(errno)));
//      close(fd);
//      goto restpriv_out;
//  }

//  if (!S_ISREG(st.st_mode)) {
//      DBG (("%s is not a regular file", userfile));
//      close(fd);
//      goto restpriv_out;
//  }

//  f = fdopen(fd, "r");
//  if (f == NULL) {
//      DBG (("fdopen: %s", strerror(errno)));
//      close(fd);
//      goto restpriv_out;
//  }

//  if (! load_chalresp_state(f, &state, cfg->debug))
//    goto restpriv_out;

//  if (fclose(f) < 0) {
//    f = NULL;
//    goto restpriv_out;
//  }
//  f = NULL;

//  if (pam_modutil_regain_priv(pamh, &privs)) {
//      DBG (("could not restore privileges"));
//      goto out;
//  }

//  if (! challenge_response(yk, state.slot, state.challenge, state.challenge_len,
//			   true, true, false,
//			   buf, sizeof(buf), &response_len)) {
//    DBG(("Challenge-response FAILED"));
//    goto out;
//  }

  /*
   * Check YubiKey response against the expected response
   */

//  yubikey_hex_encode(response_hex, buf, response_len);
//  if(state.salt_len > 0) { // the expected response has gone through pbkdf2
//    YK_PRF_METHOD prf_method = {20, yk_hmac_sha1};
//    yk_pbkdf2(response_hex, (unsigned char*)state.salt, state.salt_len, state.iterations,
//        (unsigned char*)buf, response_len, &prf_method);
//  }

//  if (memcmp(buf, state.response, state.response_len) == 0) {
//    ret = PAM_SUCCESS;
//  } else {
//    DBG(("Unexpected C/R response : %s", response_hex));
//    goto out;
//  }

//  DBG(("Got the expected response, generating new challenge (%i bytes).", CR_CHALLENGE_SIZE));

//  errstr = "Error generating new challenge, please check syslog or contact your system administrator";
//  if (generate_random(state.challenge, sizeof(state.challenge))) {
//    DBG(("Failed generating new challenge!"));
//    goto out;
//  }

//  errstr = "Error communicating with Yubikey, please check syslog or contact your system administrator";
//  if (! challenge_response(yk, state.slot, state.challenge, CR_CHALLENGE_SIZE,
//			   true, true, false,
//			   buf, sizeof(buf), &response_len)) {
//    DBG(("Second challenge-response FAILED"));
//    goto out;
//  }

  /* There is a bug that makes the YubiKey 2.2 send the same response for all challenges
     unless HMAC_LT64 is set, check for that here */
//  if (memcmp(buf, state.response, state.response_len) == 0) {
//    errstr = "Same response for second challenge, YubiKey should be reconfigured with the option HMAC_LT64";
//    goto out;
//  }

  /* the yk_* functions leave 'junk' in errno */
//  errno = 0;

  /*
   * Write the challenge and response we will expect the next time to the state file.
   */
//  if (response_len > sizeof(state.response)) {
//    DBG(("Got too long response ??? (%u/%lu)", response_len, (unsigned long) sizeof(state.response)));
//    goto out;
//  }
//  memcpy (state.response, buf, response_len);
//  state.response_len = response_len;

  /* point to the fresh privs structure.. */
//  privs = privs2;
  /* Drop privileges before creating new challenge file. */
//  if (pam_modutil_drop_priv(pamh, &privs, p)) {
//      DBG (("could not drop privileges"));
//      goto out;
//  }

  /* Write out the new file */
//  tmpfile = malloc(strlen(userfile) + 1 + 4);
//  if (! tmpfile)
//    goto restpriv_out;
//  strcpy(tmpfile, userfile);
//  strcat(tmpfile, ".tmp");

//  fd = open(tmpfile, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
//  if (fd < 0) {
//      DBG (("Cannot open file: %s (%s)", tmpfile, strerror(errno)));
//      goto restpriv_out;
//  }

//  f = fdopen(fd, "w");
//  if (! f) {
//    close(fd);
//    goto restpriv_out;
//  }

//  errstr = "Error updating Yubikey challenge, please check syslog or contact your system administrator";
//  if (! write_chalresp_state (f, &state))
//    goto out;
//  if (fclose(f) < 0) {
//    f = NULL;
//    goto restpriv_out;
//  }
//  f = NULL;
//  if (rename(tmpfile, userfile) < 0) {
//    goto restpriv_out;
//  }

//  if (pam_modutil_regain_priv(pamh, &privs)) {
//      DBG (("could not restore privileges"));
//      goto out;
//  }

//  DBG(("Challenge-response success!"));
//  errstr = NULL;
//  errno = 0;
//  goto out;

//restpriv_out:
//  if (pam_modutil_regain_priv(pamh, &privs)) {
//      DBG (("could not restore privileges"));
//  }

// out:
//  if (yk_errno) {
//    if (yk_errno == YK_EUSBERR) {
//      syslog(LOG_ERR, "USB error: %s", yk_usb_strerror());
//      DBG(("USB error: %s", yk_usb_strerror()));
//    } else {
//      syslog(LOG_ERR, "Yubikey core error: %s", yk_strerror(yk_errno));
//      DBG(("Yubikey core error: %s", yk_strerror(yk_errno)));
//    }
//  }

//  if (errstr)
//    display_error(pamh, errstr);

//  if (errno) {
//    syslog(LOG_ERR, "Challenge response failed: %s", strerror(errno));
//    DBG(("Challenge response failed: %s", strerror(errno)));
//  }

//  if (yk)
//    yk_close_key(yk);
//  yk_release();

//  if (f)
//    fclose(f);

//  free(userfile);
//  free(tmpfile);
//  return ret;
//}
//#endif /* HAVE_CR */

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
  DBG (("get user returned: %s", user));

//  if (cfg->mode == CHRESP) {
//#if HAVE_CR
//    return do_challenge_response(pamh, cfg, user);
//#else
//    DBG (("no support for challenge/response"));
//    retval = PAM_AUTH_ERR;
//    goto done;
//#endif
//  }

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

//  rc = ykclient_init (&ykc);
//  if (rc != YKCLIENT_OK)
//    {
//      DBG (("ykclient_init() failed (%d): %s", rc, ykclient_strerror (rc)));
//      retval = PAM_AUTHINFO_UNAVAIL;
//      goto done;
//    }

//  rc = ykclient_set_client_b64 (ykc, cfg->client_id, cfg->client_key);
//  if (rc != YKCLIENT_OK)
//    {
//      DBG (("ykclient_set_client_b64() failed (%d): %s",
//	    rc, ykclient_strerror (rc)));
//      retval = PAM_AUTHINFO_UNAVAIL;
//      goto done;
//    }

//  if (cfg->client_key)
//    ykclient_set_verify_signature (ykc, 1);

//  if (cfg->capath)
//    ykclient_set_ca_path (ykc, cfg->capath);

//  if (cfg->url)
//    ykclient_set_url_template (ykc, cfg->url);

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
//  rc = ykclient_request (ykc, otp);

//  DBG (("ykclient return value (%d): %s", rc,
//	ykclient_strerror (rc)));

//  switch (rc)
//    {
//    case YKCLIENT_OK:
//      break;

//    case YKCLIENT_BAD_OTP:
//    case YKCLIENT_REPLAYED_OTP:
//      retval = PAM_AUTH_ERR;
//      goto done;

//    default:
//      retval = PAM_AUTHINFO_UNAVAIL;
//      goto done;
//    }

  /* authorize the user with supplied token id */
//  if (cfg->ldapserver != NULL || cfg->ldap_uri != NULL)
//    valid_token = authorize_user_token_ldap (cfg, user, otp_id);
//  else
//    valid_token = authorize_user_token (cfg, user, otp_id, pamh);
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
//  if (ykc)
//    ykclient_done (&ykc);
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
