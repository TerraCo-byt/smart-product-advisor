import{r as x,S as e}from"./index-B1pHpRNp.js";import{c,v as u,T as y,a as A,U as g}from"./Page-BcDKyOaf.js";const C=x.createContext(!1);var s={Layout:"Polaris-Layout",Section:"Polaris-Layout__Section","Section-fullWidth":"Polaris-Layout__Section--fullWidth","Section-oneHalf":"Polaris-Layout__Section--oneHalf","Section-oneThird":"Polaris-Layout__Section--oneThird",AnnotatedSection:"Polaris-Layout__AnnotatedSection",AnnotationWrapper:"Polaris-Layout__AnnotationWrapper",AnnotationContent:"Polaris-Layout__AnnotationContent",Annotation:"Polaris-Layout__Annotation"},E={TextContainer:"Polaris-TextContainer",spacingTight:"Polaris-TextContainer--spacingTight",spacingLoose:"Polaris-TextContainer--spacingLoose"};function h({spacing:n,children:a}){const t=c(E.TextContainer,n&&E[u("spacing",n)]);return e.createElement("div",{className:t},a)}function T({children:n,title:a,description:t,id:o}){const i=typeof t=="string"?e.createElement(y,{as:"p",variant:"bodyMd"},t):t;return e.createElement("div",{className:s.AnnotatedSection},e.createElement("div",{className:s.AnnotationWrapper},e.createElement("div",{className:s.Annotation},e.createElement(h,{spacing:"tight"},e.createElement(y,{id:o,variant:"headingMd",as:"h2"},a),i&&e.createElement(A,{color:"text-secondary"},i))),e.createElement("div",{className:s.AnnotationContent},n)))}function N({children:n,variant:a}){const t=c(s.Section,s[`Section-${a}`]);return e.createElement("div",{className:t},n)}const S=function({sectioned:a,children:t}){const o=a?e.createElement(N,null,t):t;return e.createElement("div",{className:s.Layout},o)};S.AnnotatedSection=T;S.Section=N;var m={Link:"Polaris-Link",monochrome:"Polaris-Link--monochrome",removeUnderline:"Polaris-Link--removeUnderline"};function W({url:n,children:a,onClick:t,external:o,target:i,id:r,monochrome:v,removeUnderline:P,accessibilityLabel:L,dataPrimaryLink:d}){return e.createElement(C.Consumer,null,_=>{const f=v||_,p=c(m.Link,f&&m.monochrome,P&&m.removeUnderline);return n?e.createElement(g,{onClick:t,className:p,url:n,external:o,target:i,id:r,"aria-label":L,"data-primary-link":d},a):e.createElement("button",{type:"button",onClick:t,className:p,id:r,"aria-label":L,"data-primary-link":d},a)})}var l={List:"Polaris-List",typeNumber:"Polaris-List--typeNumber",Item:"Polaris-List__Item",spacingLoose:"Polaris-List--spacingLoose"};function k({children:n}){return e.createElement("li",{className:l.Item},n)}const b=function({children:a,gap:t="loose",type:o="bullet"}){const i=c(l.List,t&&l[u("spacing",t)],o&&l[u("type",o)]),r=o==="bullet"?"ul":"ol";return e.createElement(r,{className:i},a)};b.Item=k;export{S as L,W as a,b};
