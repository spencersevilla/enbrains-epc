int
local_s6a_generate_authentication_info_req (
  s6a_auth_info_req_t * air_p)
{
  struct avp                             *avp;
  struct msg                             *msg;
  struct session                         *sess;
  union avp_value                         value;

  DevAssert (air_p );
  /*
   * Create the new update location request message
   */
  CHECK_FCT (fd_msg_new (s6a_fd_cnf.dataobj_s6a_air, 0, &msg));
  /*
   * Create a new session
   */
  CHECK_FCT (fd_sess_new (&sess, fd_g_config->cnf_diamid, fd_g_config->cnf_diamid_len, (os0_t) "apps6a", 6));
  {
    os0_t                                   sid;
    size_t                                  sidlen;

    CHECK_FCT (fd_sess_getsid (sess, &sid, &sidlen));
    CHECK_FCT (fd_msg_avp_new (s6a_fd_cnf.dataobj_s6a_session_id, 0, &avp));
    value.os.data = sid;
    value.os.len = sidlen;
    CHECK_FCT (fd_msg_avp_setvalue (avp, &value));
    CHECK_FCT (fd_msg_avp_add (msg, MSG_BRW_FIRST_CHILD, avp));
  }
  CHECK_FCT (fd_msg_avp_new (s6a_fd_cnf.dataobj_s6a_auth_session_state, 0, &avp));
  /*
   * No State maintained
   */
  value.i32 = 1;
  CHECK_FCT (fd_msg_avp_setvalue (avp, &value));
  CHECK_FCT (fd_msg_avp_add (msg, MSG_BRW_LAST_CHILD, avp));
  /*
   * Add Origin_Host & Origin_Realm
   */
  CHECK_FCT (fd_msg_add_origin (msg, 0));
  mme_config_read_lock (&mme_config);
  /*
   * Destination Host
   */
  {
    bstring                                 host = bstrcpy(mme_config.s6a_config.hss_host_name);

    bconchar(host, '.');
    bconcat (host, mme_config.realm);
    CHECK_FCT (fd_msg_avp_new (s6a_fd_cnf.dataobj_s6a_destination_host, 0, &avp));
    value.os.data = (unsigned char *)bdata(host);
    value.os.len = blength(host);
    CHECK_FCT (fd_msg_avp_setvalue (avp, &value));
    CHECK_FCT (fd_msg_avp_add (msg, MSG_BRW_LAST_CHILD, avp));
    bdestroy(host);
  }
  /*
   * Destination_Realm
   */
  {
    CHECK_FCT (fd_msg_avp_new (s6a_fd_cnf.dataobj_s6a_destination_realm, 0, &avp));
    value.os.data = (unsigned char *)bdata(mme_config.realm);
    value.os.len = blength(mme_config.realm);
    CHECK_FCT (fd_msg_avp_setvalue (avp, &value));
    CHECK_FCT (fd_msg_avp_add (msg, MSG_BRW_LAST_CHILD, avp));
  }
  mme_config_unlock (&mme_config);
  /*
   * Adding the User-Name (IMSI)
   */
  CHECK_FCT (fd_msg_avp_new (s6a_fd_cnf.dataobj_s6a_user_name, 0, &avp));
  value.os.data = (unsigned char *)air_p->imsi;
  value.os.len = strlen (air_p->imsi);
  CHECK_FCT (fd_msg_avp_setvalue (avp, &value));
  CHECK_FCT (fd_msg_avp_add (msg, MSG_BRW_LAST_CHILD, avp));
  /*
   * Adding the visited plmn id
   */
  {
    uint8_t                                 plmn[3] = { 0x00, 0x00, 0x00 };     //{ 0x02, 0xF8, 0x29 };
    CHECK_FCT (fd_msg_avp_new (s6a_fd_cnf.dataobj_s6a_visited_plmn_id, 0, &avp));
    PLMN_T_TO_TBCD (air_p->visited_plmn,
                    plmn, mme_config_find_mnc_length (air_p->visited_plmn.mcc_digit1, air_p->visited_plmn.mcc_digit2, air_p->visited_plmn.mcc_digit3, air_p->visited_plmn.mnc_digit1, air_p->visited_plmn.mnc_digit2, air_p->visited_plmn.mnc_digit3)
      );
    value.os.data = plmn;
    value.os.len = 3;
    CHECK_FCT (fd_msg_avp_setvalue (avp, &value));
    CHECK_FCT (fd_msg_avp_add (msg, MSG_BRW_LAST_CHILD, avp));
    OAILOG_DEBUG (LOG_S6A, "%s plmn: %02X%02X%02X\n", __FUNCTION__, plmn[0], plmn[1], plmn[2]);
    OAILOG_DEBUG (LOG_S6A, "%s visited_plmn: %02X%02X%02X\n", __FUNCTION__, value.os.data[0], value.os.data[1], value.os.data[2]);
  }
  /*
   * Adding the requested E-UTRAN authentication info AVP
   */
  {
    struct avp                             *child_avp;

    CHECK_FCT (fd_msg_avp_new (s6a_fd_cnf.dataobj_s6a_req_eutran_auth_info, 0, &avp));
    /*
     * Add the number of requested vectors
     */
    CHECK_FCT (fd_msg_avp_new (s6a_fd_cnf.dataobj_s6a_number_of_requested_vectors, 0, &child_avp));
    value.u32 = air_p->nb_of_vectors;
    CHECK_FCT (fd_msg_avp_setvalue (child_avp, &value));
    CHECK_FCT (fd_msg_avp_add (avp, MSG_BRW_LAST_CHILD, child_avp));
    /*
     * We want to use the vectors immediately in HSS so we have to add
     * * * * the Immediate-Response-Preferred AVP.
     * * * * Value of this AVP is not significant.
     */
    CHECK_FCT (fd_msg_avp_new (s6a_fd_cnf.dataobj_s6a_immediate_response_pref, 0, &child_avp));
    value.u32 = 0;
    CHECK_FCT (fd_msg_avp_setvalue (child_avp, &value));
    CHECK_FCT (fd_msg_avp_add (avp, MSG_BRW_LAST_CHILD, child_avp));

    /*
     * Re-synchronization information containing the AUTS computed at USIM
     */
    if (air_p->re_synchronization) {
      CHECK_FCT (fd_msg_avp_new (s6a_fd_cnf.dataobj_s6a_re_synchronization_info, 0, &child_avp));
      // TODO Fix after updating HSS
      value.os.len = AUTS_LENGTH;
      value.os.data = (air_p->resync_param + RAND_LENGTH_OCTETS);
      CHECK_FCT (fd_msg_avp_setvalue (child_avp, &value));
      CHECK_FCT (fd_msg_avp_add (avp, MSG_BRW_LAST_CHILD, child_avp));
    }

    CHECK_FCT (fd_msg_avp_add (msg, MSG_BRW_LAST_CHILD, avp));
  }

  // SMS: ONLY MODIFICATION IS TO CHANGE THIS LINE TO ONE THAT PASSES INTERNALLY
  return local_s6a_auth_info_cb(&msg);
  // CHECK_FCT (fd_msg_send (&msg, NULL, NULL));
  // return RETURNok;
}



////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////



int
local_s6a_auth_info_cb (struct msg **msg)
{
  struct msg                             *ans = NULL,
                                         *qry = NULL;
  struct avp                             *avp = NULL,
                                         *failed_avp = NULL;
  struct avp_hdr                         *hdr = NULL;
  union avp_value                         value;

  /*
   * Database queries
   */
  mysql_auth_info_req_t                   auth_info_req;
  mysql_auth_info_resp_t                  auth_info_resp;

  /*
   * Authentication vector
   */
  auc_vector_t                            vector[AUTH_MAX_EUTRAN_VECTORS];
  int                                     ret = 0;
  int                                     result_code = ER_DIAMETER_SUCCESS;
  int                                     experimental = 0;
  uint64_t                                imsi = 0;
  uint32_t                                num_vectors = 0;
  uint8_t                                *sqn = NULL,
    *auts = NULL;

  if (msg == NULL) {
    return EINVAL;
  }

  /*
   * Create answer header
   */
  qry = *msg;
  CHECK_FCT (fd_msg_new_answer_from_req (fd_g_config->cnf_dict, msg, 0));
  ans = *msg;
  /*
   * Retrieving IMSI AVP: User-Name
   */
  CHECK_FCT (fd_msg_search_avp (qry, s6a_cnf.dataobj_s6a_imsi, &avp));

  if (avp) {
    CHECK_FCT (fd_msg_avp_hdr (avp, &hdr));

    if (hdr->avp_value->os.len > IMSI_LENGTH_MAX) {
      result_code = ER_DIAMETER_INVALID_AVP_VALUE;
      goto out;
    }

    sprintf (auth_info_req.imsi, "%*s", (int)hdr->avp_value->os.len, hdr->avp_value->os.data);
    sscanf (auth_info_req.imsi, "%" SCNu64, &imsi);
  } else {
    result_code = ER_DIAMETER_MISSING_AVP;
    goto out;
  }

  /*
   * Retrieving Supported Features AVP. This is an optional AVP.
   */
  CHECK_FCT (fd_msg_search_avp (qry, s6a_cnf.dataobj_s6a_supported_features, &avp));

  if (avp) {
    CHECK_FCT (fd_msg_avp_hdr (avp, &hdr));
  }

  /*
   * Retrieving the Requested-EUTRAN-Authentication-Info.
   * * * * If this AVP is not present, we have to check for
   * * * * Requested-GERAN-Authentication-Info AVP which will mean that the request
   * * * * comes from RAT other than E-UTRAN, case not handled by this HSS
   * * * * implementation.
   */
  CHECK_FCT (fd_msg_search_avp (qry, s6a_cnf.dataobj_s6a_req_e_utran_auth_info, &avp));

  if (avp) {
    struct avp                             *child_avp;

    /*
     * Walk through childs avp
     */
    CHECK_FCT (fd_msg_browse (avp, MSG_BRW_FIRST_CHILD, &child_avp, NULL));

    while (child_avp) {
      /*
       * Retrieve the header of the child avp
       */
      CHECK_FCT (fd_msg_avp_hdr (child_avp, &hdr));

      switch (hdr->avp_code) {
      case AVP_CODE_NUMBER_OF_REQ_VECTORS:{
          /*
           * We allow only one vector request
           */
          if (hdr->avp_value->u32 > AUTH_MAX_EUTRAN_VECTORS) {
            result_code = ER_DIAMETER_INVALID_AVP_VALUE;
            failed_avp = child_avp;
            goto out;
          }
          num_vectors = hdr->avp_value->u32;
        }
        break;

      case AVP_CODE_IMMEDIATE_RESP_PREF:
        /*
         * We always respond immediately to the request
         */
        break;

      case AVP_CODE_RE_SYNCHRONIZATION_INFO:

        /*
         * The resynchronization-info AVP is present.
         * * * * AUTS = Conc(SQN MS ) || MAC-S
         */
        if (avp) {
          auts = hdr->avp_value->os.data;
        }

        break;

      default:{
          /*
           * This AVP is not expected on s6a interface
           */
          result_code = ER_DIAMETER_AVP_UNSUPPORTED;
          failed_avp = child_avp;
          goto out;
        }
      }

      /*
       * Go to next AVP in the grouped AVP
       */
      CHECK_FCT (fd_msg_browse (child_avp, MSG_BRW_NEXT, &child_avp, NULL));
    }
  } else {
    CHECK_FCT (fd_msg_search_avp (qry, s6a_cnf.dataobj_s6a_req_geran_auth_info, &avp));

    if (avp) {
      result_code = DIAMETER_ERROR_RAT_NOT_ALLOWED;
      experimental = 1;
      goto out;
    } else {
      result_code = ER_DIAMETER_INVALID_AVP_VALUE;
      failed_avp = avp;
      goto out;
    }
  }

  /*
   * Retrieving the Visited-PLMN-Id AVP
   */
  CHECK_FCT (fd_msg_search_avp (qry, s6a_cnf.dataobj_s6a_visited_plmn_id, &avp));

  if (avp) {
    /*
     * TODO: check PLMN and allow/reject connectivity depending on roaming
     */
    CHECK_FCT (fd_msg_avp_hdr (avp, &hdr));

    if (hdr->avp_value->os.len == 3) {
      if (apply_access_restriction (auth_info_req.imsi, hdr->avp_value->os.data) != 0) {
        /*
         * We found that user is roaming and has no right to do it ->
         * * * * reject the connection
         */
        result_code = DIAMETER_ERROR_ROAMING_NOT_ALLOWED;
        experimental = 1;
        goto out;
      }
    } else {
      result_code = ER_DIAMETER_INVALID_AVP_VALUE;
      goto out;
    }
  } else {
    /*
     * Mandatory AVP, raise an error if not present
     */
    result_code = ER_DIAMETER_MISSING_AVP;
    goto out;
  }

  /*
   * Fetch User data
   */
  if (hss_mysql_auth_info (&auth_info_req, &auth_info_resp) != 0) {
    /*
     * Database query failed...
     */
    result_code = DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE;
    experimental = 1;
    goto out;
  }

  if (auts != NULL) {
    /*
     * Try to derive SQN_MS from previous RAND
     */
    sqn = sqn_ms_derive (auth_info_resp.opc, auth_info_resp.key, auts, auth_info_resp.rand);

    if (sqn != NULL) {
      /*
       * We succeeded to verify SQN_MS...
       */
      /*
       * Pick a new RAND and store SQN_MS + RAND in the HSS
       */
      generate_random (vector[0].rand, RAND_LENGTH);
      hss_mysql_push_rand_sqn (auth_info_req.imsi, vector[0].rand, sqn);
      hss_mysql_increment_sqn (auth_info_req.imsi);
      free (sqn);
    }

    /*
     * Fetch new user data
     */
    if (hss_mysql_auth_info (&auth_info_req, &auth_info_resp) != 0) {
      /*
       * Database query failed...
       */
      result_code = DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE;
      experimental = 1;
      goto out;
    }

    sqn = auth_info_resp.sqn;
    for (int i = 0; i < num_vectors; i++) {
      generate_random (vector[i].rand, RAND_LENGTH);
      generate_vector (auth_info_resp.opc, imsi, auth_info_resp.key, hdr->avp_value->os.data, sqn, &vector[i]);
    }
    hss_mysql_push_rand_sqn (auth_info_req.imsi, vector[num_vectors-1].rand, sqn);
  } else {
    /*
     * Pick a new RAND and store SQN_MS + RAND in the HSS
     */
    for (int i = 0; i < num_vectors; i++) {
      generate_random (vector[i].rand, RAND_LENGTH);
      sqn = auth_info_resp.sqn;
      /*
       * Generate authentication vector
       */
      generate_vector (auth_info_resp.opc, imsi, auth_info_resp.key, hdr->avp_value->os.data, sqn, &vector[i]);
    }
    hss_mysql_push_rand_sqn (auth_info_req.imsi, vector[num_vectors-1].rand, sqn);
  }

  hss_mysql_increment_sqn (auth_info_req.imsi);
  /*
   * We add the vector
   */
  {
    struct avp                             *e_utran_vector,
                                           *child_avp;
    for (int i = 0; i < num_vectors; i++) {
      CHECK_FCT (fd_msg_avp_new (s6a_cnf.dataobj_s6a_authentication_info, 0, &avp));
      CHECK_FCT (fd_msg_avp_new (s6a_cnf.dataobj_s6a_e_utran_vector, 0, &e_utran_vector));
      CHECK_FCT (fd_msg_avp_new (s6a_cnf.dataobj_s6a_rand, 0, &child_avp));
      value.os.data = vector[i].rand;
      value.os.len = RAND_LENGTH_OCTETS;
      CHECK_FCT (fd_msg_avp_setvalue (child_avp, &value));
      CHECK_FCT (fd_msg_avp_add (e_utran_vector, MSG_BRW_LAST_CHILD, child_avp));
      CHECK_FCT (fd_msg_avp_new (s6a_cnf.dataobj_s6a_xres, 0, &child_avp));
      value.os.data = vector[i].xres;
      value.os.len = XRES_LENGTH_OCTETS;
      CHECK_FCT (fd_msg_avp_setvalue (child_avp, &value));
      CHECK_FCT (fd_msg_avp_add (e_utran_vector, MSG_BRW_LAST_CHILD, child_avp));
      CHECK_FCT (fd_msg_avp_new (s6a_cnf.dataobj_s6a_autn, 0, &child_avp));
      value.os.data = vector[i].autn;
      value.os.len = AUTN_LENGTH_OCTETS;
      CHECK_FCT (fd_msg_avp_setvalue (child_avp, &value));
      CHECK_FCT (fd_msg_avp_add (e_utran_vector, MSG_BRW_LAST_CHILD, child_avp));
      CHECK_FCT (fd_msg_avp_new (s6a_cnf.dataobj_s6a_kasme, 0, &child_avp));
      value.os.data = vector[i].kasme;
      value.os.len = KASME_LENGTH_OCTETS;
      CHECK_FCT (fd_msg_avp_setvalue (child_avp, &value));
      CHECK_FCT (fd_msg_avp_add (e_utran_vector, MSG_BRW_LAST_CHILD, child_avp));
      CHECK_FCT (fd_msg_avp_add (avp, MSG_BRW_LAST_CHILD, e_utran_vector));
      CHECK_FCT (fd_msg_avp_add (ans, MSG_BRW_LAST_CHILD, avp));
    }
  }
out:
  /*
   * Add the Auth-Session-State AVP
   */
  CHECK_FCT (fd_msg_search_avp (qry, s6a_cnf.dataobj_s6a_auth_session_state, &avp));
  CHECK_FCT (fd_msg_avp_hdr (avp, &hdr));
  CHECK_FCT (fd_msg_avp_new (s6a_cnf.dataobj_s6a_auth_session_state, 0, &avp));
  CHECK_FCT (fd_msg_avp_setvalue (avp, hdr->avp_value));
  CHECK_FCT (fd_msg_avp_add (ans, MSG_BRW_LAST_CHILD, avp));
  /*
   * Append the result code to the answer
   */
  CHECK_FCT (s6a_add_result_code (ans, failed_avp, result_code, experimental));

  // SMS: ONLY MODIFICATION IS TO KEEP PASSING THIS MESSAGE STRING AROUND...
  return local_s6a_aia_cb(msg);
  // CHECK_FCT (fd_msg_send (msg, NULL, NULL));
  // return ret;
}



////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////



int
local_s6a_aia_cb (struct msg **msg)
{
  struct msg                             *ans = NULL;
  struct msg                             *qry = NULL;
  struct avp                             *avp = NULL;
  struct avp_hdr                         *hdr = NULL;
  MessageDef                             *message_p = NULL;
  s6a_auth_info_ans_t                    *s6a_auth_info_ans_p = NULL;
  int                                     skip_auth_res = 0;

  DevAssert (msg );
  ans = *msg;
  /*
   * Retrieve the original query associated with the asnwer
   */
  CHECK_FCT (fd_msg_answ_getq (ans, &qry));
  DevAssert (qry );
  message_p = itti_alloc_new_message (TASK_S6A, S6A_AUTH_INFO_ANS);
  s6a_auth_info_ans_p = &message_p->ittiMsg.s6a_auth_info_ans;
  OAILOG_DEBUG (LOG_S6A, "Received S6A Authentication Information Answer (AIA)\n");
  CHECK_FCT (fd_msg_search_avp (qry, s6a_fd_cnf.dataobj_s6a_user_name, &avp));

  if (avp) {
    CHECK_FCT (fd_msg_avp_hdr (avp, &hdr));
    snprintf (s6a_auth_info_ans_p->imsi, (int)hdr->avp_value->os.len + 1,
              "%*s", (int)hdr->avp_value->os.len, hdr->avp_value->os.data);
  } else {
    DevMessage ("Query has been freed before we received the answer\n");
  }

  /*
   * Retrieve the result-code
   */
  CHECK_FCT (fd_msg_search_avp (ans, s6a_fd_cnf.dataobj_s6a_result_code, &avp));

  if (avp) {
    CHECK_FCT (fd_msg_avp_hdr (avp, &hdr));
    s6a_auth_info_ans_p->result.present = S6A_RESULT_BASE;
    s6a_auth_info_ans_p->result.choice.base = hdr->avp_value->u32;
    MSC_LOG_TX_MESSAGE (MSC_S6A_MME, MSC_NAS_MME, NULL, 0, "0 S6A_AUTH_INFO_ANS imsi %s %s", s6a_auth_info_ans_p->imsi, retcode_2_string (s6a_auth_info_ans_p->result.choice.base));

    if (hdr->avp_value->u32 != ER_DIAMETER_SUCCESS) {
      OAILOG_ERROR (LOG_S6A, "Got error %u:%s\n", hdr->avp_value->u32, retcode_2_string (hdr->avp_value->u32));
      skip_auth_res = 1;
    } else {
      OAILOG_DEBUG (LOG_S6A, "Received S6A Result code %u:%s\n", s6a_auth_info_ans_p->result.choice.base, retcode_2_string (s6a_auth_info_ans_p->result.choice.base));
    }
  } else {
    /*
     * The result-code is not present, may be it is an experimental result
     * * * * avp indicating a 3GPP specific failure.
     */
    CHECK_FCT (fd_msg_search_avp (ans, s6a_fd_cnf.dataobj_s6a_experimental_result, &avp));

    if (avp) {
      /*
       * The procedure has failed within the HSS.
       * * * * NOTE: contrary to result-code, the experimental-result is a grouped
       * * * * AVP and requires parsing its childs to get the code back.
       */
      s6a_auth_info_ans_p->result.present = S6A_RESULT_EXPERIMENTAL;
      s6a_parse_experimental_result (avp, &s6a_auth_info_ans_p->result.choice.experimental);
      MSC_LOG_TX_MESSAGE (MSC_S6A_MME, MSC_NAS_MME, NULL, 0, "0 S6A_AUTH_INFO_ANS imsi %s %s", s6a_auth_info_ans_p->imsi, experimental_retcode_2_string (s6a_auth_info_ans_p->result.choice.experimental));
      skip_auth_res = 1;
    } else {
      /*
       * Neither result-code nor experimental-result is present ->
       * * * * totally incorrect behaviour here.
       */
      MSC_LOG_TX_MESSAGE_FAILED (MSC_S6A_MME, MSC_NAS_MME, NULL, 0, "0 S6A_AUTH_INFO_ANS imsi %s", s6a_auth_info_ans_p->imsi);
      OAILOG_ERROR (LOG_S6A, "Experimental-Result and Result-Code are absent: " "This is not a correct behaviour\n");
      goto err;
    }
  }

  if (skip_auth_res == 0) {
    CHECK_FCT (fd_msg_search_avp (ans, s6a_fd_cnf.dataobj_s6a_authentication_info, &avp));

    if (avp) {
      CHECK_FCT (s6a_parse_authentication_info_avp (avp, &s6a_auth_info_ans_p->auth_info));
    } else {
      DevMessage ("We requested E-UTRAN vectors with an immediate response...\n");
      return RETURNerror;
    }
  }

  // SMS: THIS IS OUR ACTUAL EXIT-POINT
  itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
err:
  // SMS: BREAK HERE?
  return RETURNok;
}
