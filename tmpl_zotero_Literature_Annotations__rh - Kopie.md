---
{# nunjucks-template to import zotero sources into obsidian via 'zotero integration plugin' -#}
{# Save as *.md file. -#}
{# Inspired partly by Elena Razlogova. -#}
{# Three underscores at begin of line -> horizontal line. -#}
{# Minus sign at beginning/end of comment eats up spaces, but not: -#}
{# \n == two spaces at begin of line  -#}
{# https://github.com/alex-kline/obsidian-zotero/ -#}
{% if citekey %}title: {{citekey}}{% endif %}
cssclass: research-s_content
{% set vars = [
  { "name": "key", "value": key },
  { "name": "title", "value": title },
  { "name": "publicationTitle", "value": publicationTitle },
  { "name": "authors", "value": authors },
  { "name": "itemType", "value": itemType },
  { "name": "archive", "value": archive },
  { "name": "archiveLocation", "value": archiveLocation },
  { "name": "uri", "value": uri },
  { "name": "desktopURI", "value": desktopURI },
  { "name": "pdfZoteroLink", "value": pdfZoteroLink },
  { "name": "attachment.path", "value": attachment.path }
] -%}
{% if vars | selectattr("value") | list | length > 0 -%}
zotero_fields:
   # 'fields' of source exported from zotero via zotero integration plugin to obsidian .
   # see: https://www.zotero.org/support/kb/item_types_and_fields
{% if citekey %}   citekey: {{citekey}}{% endif %}
{% for v in vars %}
   {%- if v.value %}   {{ v.name }}: "{{ v.value }}"{% else %}   {{ v.name }}: ""
   {%- endif %}
{% endfor %}{% endif -%}
{% if date %}   date: {{date | format("YYYY-MM-DD")}}{% endif %}
{% if dateAdded %}   dateAdded: {{dateAdded | format("YYYY-MM-DD")}}{% endif %} 
{% if dateModified %}   dateModified: {{dateModified | format("YYYY-MM-DD")}}{% endif %}
{% if importDate %}   importDate: {{importDate | format("YYYY-MM-DD hh:mm")}}{% endif %}
{% if tags.length > 0 %}   tags: {% for t in tags -%}#{{t.tag | lower | replace(" ", "-") }}{% endfor %}{% endif %}
{% if bibliography %}   bibliography: "{{bibliography | replace("[1]", "") | trim }}"{% endif %}
{#- Cause of difficulties to open pdf in zotero (if not attachment !?): #}
   # Cause of difficulties to open pdf in zotero (if not attachment !?) via @zotero_citekey:
   # 'pdfZoteroLink' modified to '[pdf_Zot_Lnk]': seems to successfully open the pdf in zotero.
{% if pdfZoteroLink %}{% set pdfZoteroLinkModified = pdfZoteroLink | replace("select", "open-pdf") | replace(r/\[.+\]/, '') | replace('(', '') | replace(')', '') %}{% endif -%}
{% if pdfZoteroLinkModified %}   pdfZoteroLinkModified: "{{pdfZoteroLinkModified}}"{% endif %}
{# {% if pdfZoteroLink %}   pdfZoteroLinkModified: "{{pdfZoteroLink | replace("select", "open-pdf") | replace(r/\[.+\]/, '[pdf_Zot_Lnk]')}}"{% endif %}  -#}
{# citekey: {{citekey}} -#}
{#  -#}
{# san_ == 'split_in_atomic_notes' -#}
san_nunjucks_template: 
   name: "tmpl_zotero_Literature_Annotations__rh.nunjucks"
   doc: "split_zotero_note_to_annotation_atomic_notes"
   version: "0.2"
   date: 2025-10-01
---
{# Properties / frontmatter : End -#}
{{bibliography | replace("[1]", "") | trim}}
{# [online]({{uri}})    [pdf](file://{{attachment.path | replace(" ", "%20")}}) -#}
[local]({{desktopURI}}) {%- for attachment in attachments | filterby("path", "endswith", ".pdf") %}     {% if loop.last %}{% endif %}{%- endfor %} 
{% if date %}date: {{date | format("YYYY-MM-DD")}}{% endif -%}
{% if importDate %}           Import: {{importDate | format("YYYY-MM-DD hh:mm")}}{% endif %}
___
{# comments in md are sourrounded by '%%' -#}
{% persist "preamble" -%}{# nunjucks adds: >%% begin preamble %%< -#}
{%- if isFirstImport %}
{% if title %}## {{title}}{% endif %}
### Résumé                                %% note summary %%  
### Zusammenhänge                         %% note connections %%  
### Kommentar                             %% note comment %%  
{# {% if notes.length > 0 -%}
{% for note in notes %}{{note.note}}{% endfor %}
{% endif -%} #}
### Tags                                    %% note tags %% 
{% if notes.length > 0 -%}
{% for note in notes %}{% for t in note.tags %}#{{t.tag | lower | replace(" ", "_")}} {% endfor %}{% endfor %}
{% endif -%}
### QA                                      %% note QA %% 
#QA_ToDo
  
{% endif -%}
{% endpersist %}{# nunjucks adds: >%% end preamble %%< -#}
{% macro calloutHeader(color) -%}
{%- if color == "#ff6666" -%}Definition{%- endif -%}{# red #}
{%- if color == "#5fb236" -%}Argumentation{%- endif -%}{# green #}
{%- if color == "#2ea8e5" -%}Zusammenfassung{%- endif -%}{# blue #}
{%- if color == "#a28ae5" -%}Konklusion{%- endif -%}{# Purple #}
{%- if color == "#e56eee" -%}These{%- endif -%}{# Magenta #}
{%- if color == "#f19837" -%}Faktum{%- endif -%}{# Orange #}
{%- if color == "#aaaaaa" -%}Referenzen{%- endif -%}{# Grey #}
{%- endmacro -%}
{# Annotations : Begin -#}
{% persist "annotations" -%}{# nunjucks adds: >%% begin annotations %%< -#}
{% set annotations = annotations | filterby("date", "dateafter", lastImportDate) -%}
{% if annotations.length > 0 %}
{%- for annotation in annotations %}
___ 
%% Annotation_{{annotation.id}}: Begin %% 
{# ###### {{annotation.id}} -#}
{% if annotation.imageRelativePath %}![[{{annotation.imageRelativePath}}]] {%- endif -%}
{# use annotation.color to modify header: -#}
{% if annotation.annotatedText -%}
{% if annotation.color !== "#ffd400" %}## {{calloutHeader(annotation.color)}}  {% else %}## Zitat:  {% endif %}  %% note citation title %%
{# highlight referneces in red -#}
{{ annotation.annotatedText | replace(r/\[(\d+)\]/g, '<span style="color:red;">[$1]</span>') }}
### Bibliographie (Referenzen im Zitat)          %% annotation bibliography %% 
{% set regex_reference = r/\[\d+\]/ -%}{% if regex_reference.test(annotation.annotatedText) %}Fehlende Referenz ?{% endif %}
### Kommentar                                    %% annotation comment %% 
{% if annotation.comment %}{{annotation.comment}}{% else %}...{% endif %}
### Tags                                    %% annotation tags %% 
{% if annotation.tags.length > 0 -%}{% for t in annotation.tags -%}#{{t.tag | lower | replace(" ", "_")}}{%- endfor %}{% else %} -- {%- endif %}
### QA                                      %% annotation QA %% 
#QA_ToDo #QA_update #QA_ok #QA_na
___
{% set separator = "    ≡≡≡    " -%}
Quelle: @{{citekey}}{{ separator }}{{firstAttachmentZoteroLink}}
{%- if annotation.desktopURI %}{{ separator }}[Go to annotation]({{annotation.desktopURI}}){% endif %}
{%- if annotation.selectURI %}{{ separator }}[Open in Zotero]({{annotation.selectURI}}){% endif %}
{%- if pdfZoteroLinkModified  %}{{ separator }}[Open in Zotero]({{pdfZoteroLinkModified}}){%- endif %}{% endif %} 
%% Annotation_{{annotation.id}}: End %%
{%- endfor %}{% endif %}
___
{% endpersist %}{# nunjucks adds: >%% end annotations %%< #}
{# Annotations : End -#}