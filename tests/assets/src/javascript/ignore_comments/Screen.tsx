export function Screen({ html, other }) {
  eval(other); // mobsf-ignore: js_dynamic_code_execution
  return (
    <div>
      <p dangerouslySetInnerHTML={{ __html: html }} /> {/* mobsf-ignore: js_dom_xss_sink*/}
      <span dangerouslySetInnerHTML={{ __html: other }} />
    </div>
  );
}
