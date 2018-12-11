#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define dec_int16(s) ((((unsigned char*)  (s))[0] << 8) | \
                      (((unsigned char*)  (s))[1]))

#define enc_int16(i, s) {((unsigned char*)(s))[0] = ((i) >> 8) & 0xff; \
                        ((unsigned char*)(s))[1] = (i)         & 0xff;}

#define BUFSIZE (1 << 16)
#define CMD_AUTH 0
#define CMD_ACCT 1
#define CMD_CHAUTHTOK 2

typedef unsigned char byte;

typedef struct _conv_func_rec {
  const char * prompt;
  void (*func)(struct pam_response **resp, void * password);
} conv_func_rec;

#define CURRENT_PWD_PROMPT "Current password:"
#define NEW_PWD_PROMPT "New password:"
#define RETYPE_PWD_PROMPT "Retype new password:"
#define PWD_PROMPT "Password:"

#ifdef PAM_FAIL_DELAY
static void delay_fn(int retval, unsigned usec_delay, void *appdata_ptr)
{
  /* No delay. However, looks like some PAM modules ignore this */
}
#endif

static void _auth_passwd(struct pam_response **resp, void * password)
{
  (*resp)[0].resp = strdup((char *) password);
}

static void _chauthtok_cur_passwd(struct pam_response ** resp, void * password)
{
  char ** passwd = (char**) password;
  (*resp)[0].resp = strdup(passwd[0]);
}

static void _chauthtok_new_passwd(struct pam_response ** resp, void * password)
{
  char ** passwd = (char**) password;
  (*resp)[0].resp = strdup(passwd[1]);
}

static conv_func_rec conv_func_tbl[] = {{PWD_PROMPT, _auth_passwd},
                                        {CURRENT_PWD_PROMPT, _chauthtok_cur_passwd},
                                        {NEW_PWD_PROMPT, _chauthtok_new_passwd},
                                        {RETYPE_PWD_PROMPT, _chauthtok_new_passwd},
                                        0};

static void _conv_response(const struct pam_message **m,
                           struct pam_response ** r,
                           void * p)
{
  conv_func_rec * i = conv_func_tbl;
  
  while (strncmp(m[0]->msg, i->prompt, strlen(i->prompt)) != 0)
    i++;
  i->func(r, p);  
}


int misc_conv(int num_msg,
              const struct pam_message **msg,
              struct pam_response **resp,
              void *password)
{
  int msg_style;

  if (num_msg != 1)
    return PAM_CONV_ERR;

  msg_style = msg[0]->msg_style;

  if ((msg_style != PAM_PROMPT_ECHO_OFF) &&
      (msg_style != PAM_PROMPT_ECHO_ON))
    return PAM_CONV_ERR;

  *resp = malloc(sizeof(struct pam_response));
  (*resp)[0].resp_retcode = 0;

  _conv_response(msg, resp, password);
  
  return PAM_SUCCESS;
}

static int auth(char *service, char *user, char *password)
{
  struct pam_conv conv = {misc_conv, password};
  int retval;
  pam_handle_t *pamh = NULL;
  retval = pam_start(service, user, &conv, &pamh);
  if (retval == PAM_SUCCESS)
    retval = pam_set_item(pamh, PAM_RUSER, user);
#ifdef PAM_FAIL_DELAY
  if (retval == PAM_SUCCESS)
    retval = pam_set_item(pamh, PAM_FAIL_DELAY, (void *)delay_fn);
#endif
  if (retval == PAM_SUCCESS)
    retval = pam_authenticate(pamh, 0);
  if (retval == PAM_SUCCESS)
    retval = pam_acct_mgmt(pamh, 0);
  pam_end(pamh, retval);
  return retval;
}

static int chauthtok(char *service, char *user, char ** password)
{
  struct pam_conv conv = {misc_conv, (void *) password};
  int retval;
  pam_handle_t *pamh = NULL;

  retval = pam_start(service, user, &conv, &pamh);

  if (retval == PAM_SUCCESS)
    retval = pam_set_item(pamh, PAM_RUSER, user);
    
#ifdef PAM_FAIL_DELAY
  if (retval == PAM_SUCCESS)
    retval = pam_set_item(pamh, PAM_FAIL_DELAY, (void *)delay_fn);
#endif

  if (retval == PAM_SUCCESS)
    retval = pam_chauthtok(pamh, PAM_SILENT);

  pam_end(pamh, retval);
  
  return retval;
}

static int process_auth()
{
  int retval = 0;
  char *service, *username, *password, *remote_host;
  service = "login";
  username = "epam";
  password = "hello1";
  retval = auth(service, username, password);
  return retval;
}

static int process_chauthtok()
{
  int retval = 0;
  char *service, *username, *opasswd, *npasswd;
  char * password[2];
  
  service = "passwd";
  username = "epam";
  opasswd = "hello";
  npasswd = "hello1";
  
  password[0] = opasswd;
  password[1] = npasswd;
  
  retval = chauthtok(service, username, password);
  
  return retval;
}

int main(int argc, char *argv[])
{
  fprintf(stderr, "debug %d\n", process_chauthtok());
  fprintf(stderr, "debug %d\n", process_auth());
  return 0;
}
