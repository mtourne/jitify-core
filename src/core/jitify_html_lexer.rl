#include <stdio.h>
#define JITIFY_INTERNAL
#include "jitify_css.h"
#include "jitify_html.h"

/* HTML grammar based on http://www.w3.org/TR/WD-html-lex/
 */

%%{
  machine jitify_html;
  include jitify_common "jitify_lexer_common.rl";
  include css_grammar   "jitify_css_lexer_common.rl";

  tag_close = '/'? @{ state->trailing_slash = 1; } '>';

  name_char = (alnum | '-' | '_' | '.' | ':');
  name_start_char = (alpha | '_');
  name = name_start_char name_char**;

  action leave_content {
    TOKEN_END;
  }

  conditional_comment = '[' ('if'i | 'endif') %{ state->conditional_comment = 1; };

  comment = '--' %{ TOKEN_TYPE(jitify_type_html_comment); state->conditional_comment = 0; }
    (any | conditional_comment)* :>> '-->' %{ TOKEN_END; };

  misc_directive = any* :>> '>';

  directive = (
    '!' (comment | misc_directive)
  );

  attr_name = (
    alpha (alnum | '-' | '_' | ':')**
  )
    >{ ATTR_KEY_START; }
    %{ ATTR_KEY_END; };

  unquoted_attr_char = ( any - ( space | '>' | '\\' | '"' | "'" ) );
  unquoted_attr_value = (unquoted_attr_char unquoted_attr_char**)
    >{ ATTR_VALUE_START;
       ATTR_SET_QUOTE(0); }
    %{ ATTR_VALUE_END; };

  single_quoted_attr_value = "'" @{ ATTR_SET_QUOTE('\''); }
  ( /[^']*/ ) >{ ATTR_VALUE_START; } %{ ATTR_VALUE_END; }
  "'";

  double_quoted_attr_value = '"' @{ ATTR_SET_QUOTE('"'); }
  ( /[^"]*/ )
    >{ ATTR_VALUE_START; }
    %{ ATTR_VALUE_END; }
  '"';

  attr_value = (
    unquoted_attr_value |
    single_quoted_attr_value  |
    double_quoted_attr_value
  );

  unparsed_attr_name = (
    alpha (alnum | '-' | '_' | ':')*
  );

  unparsed_attr_value = (
    ( any - ( space | '>' | '\\' | '"' | "'" ) )+ |
    "'" /[^']*/ "'" |
    '"' /[^"]*/ '"'
  );

  unparsed_attr = (
    unparsed_attr_name space* ('=' space* unparsed_attr_value)?
  );

  preformatted_close = '</' /(pre|textarea)/i '>' @{ state->nominify_depth--; };

  preformatted_open= (/pre/i | /textarea/i) @{ state->nominify_depth++; }
    (space+ unparsed_attr)* space* tag_close;

  script_close = '</' /script/i '>';

  tag_attrs = (space+ %{ ATTR_END;} ( attr_name <: space* ( '=' space* attr_value <: space*)? )*);

  script = (
    /script/i
      >{ ATTR_KEY_START; }
      %{ TOKEN_TYPE(jitify_type_html_tag);
         ATTR_KEY_END; }
    tag_attrs? tag_close
      %{ TOKEN_END;
         TOKEN_START(jitify_token_type_misc); }
      (any* - ( any* script_close any* ) ) script_close
  );

  style = (
    /style/i
      >{ ATTR_KEY_START; }
      %{ TOKEN_TYPE(jitify_type_html_tag);
         ATTR_KEY_END; }
    tag_attrs? tag_close
      %{ TOKEN_END; }
    css_document? ( '</' /style/i '>' )
      >{ TOKEN_TYPE(jitify_token_type_misc); }
      %{ TOKEN_END; }
  );

  misc_tag = (
    '/'?
      @{ state->leading_slash = 1; }
    attr_name
    tag_attrs?
    tag_close
  )
    >{ TOKEN_TYPE(jitify_type_html_tag); };

  _xml_tag_close = '?>';

  xml_tag = ( '?' (any* - _xml_tag_close) :>> _xml_tag_close )
    >{ TOKEN_TYPE(jitify_token_type_misc); };

  element = (
    script
    |
    xml_tag
    |
    style
    |
    misc_tag
    |
    directive
  );

  html_space = (
    ( space - ( '\r' | '\n' ) ) |
    ( '\r' | '\n' ) @{ state->space_contains_newlines = 1; }
  )+
    >{ TOKEN_START(jitify_type_html_space);
       state->space_contains_newlines = 0; }
    %{ TOKEN_END; };

  content = (
    any - (space | '<' )
  )+
    >{ TOKEN_START(jitify_token_type_misc); }
    %{ TOKEN_END; };

  main := (
    byte_order_mark?
    (
      ( '<'
          >{ TOKEN_START(jitify_token_type_misc);
            state->leading_slash = 0;
            state->trailing_slash = 0; }
        element
          %{ TOKEN_END;
             RESET_ATTRS; }
      )
      |
      html_space
      |
      content
    )**
  ) $err(main_err);

  write data;
}%%

int jitify_html_scan(jitify_lexer_t *lexer, const void *data, size_t length, int is_eof)
{
  const char *p = data, *pe = p + length;
  const char *eof = is_eof ? pe : NULL;
  jitify_html_state_t *state = lexer->state;
  if (!lexer->initialized) {
    %% write init;
    lexer->initialized = 1;
  }
  %% write exec;
  return p - (const char *)data;
}
