import{r as v,j as e}from"./index-B1pHpRNp.js";import{R as f,_ as y}from"./index-DrlDjJDS.js";import{a as k}from"./components-CnYr-nWG.js";import{P as w,B as s,C as d,T as r,I as i,b as m,a as j}from"./Page-BcDKyOaf.js";import{L as o,a,b as l}from"./List-CzfswqJc.js";import"./context-CjnOB2vb.js";function C(){var h,u,x,g;const t=k(),p=f(),b=["loading","submitting"].includes(t.state)&&t.formMethod==="POST",n=(u=(h=t.data)==null?void 0:h.product)==null?void 0:u.id.replace("gid://shopify/Product/","");v.useEffect(()=>{n&&p.toast.show("Product created")},[n,p]);const c=()=>t.submit({},{method:"POST"});return e.jsxs(w,{children:[e.jsx(y,{title:"Remix app template",children:e.jsx("button",{variant:"primary",onClick:c,children:"Generate a product"})}),e.jsx(s,{gap:"500",children:e.jsxs(o,{children:[e.jsx(o.Section,{children:e.jsx(d,{children:e.jsxs(s,{gap:"500",children:[e.jsxs(s,{gap:"200",children:[e.jsx(r,{as:"h2",variant:"headingMd",children:"Congrats on creating a new Shopify app 🎉"}),e.jsxs(r,{variant:"bodyMd",as:"p",children:["This embedded app template uses"," ",e.jsx(a,{url:"https://shopify.dev/docs/apps/tools/app-bridge",target:"_blank",removeUnderline:!0,children:"App Bridge"})," ","interface examples like an"," ",e.jsx(a,{url:"/app/additional",removeUnderline:!0,children:"additional page in the app nav"}),", as well as an"," ",e.jsx(a,{url:"https://shopify.dev/docs/api/admin-graphql",target:"_blank",removeUnderline:!0,children:"Admin GraphQL"})," ","mutation demo, to provide a starting point for app development."]})]}),e.jsxs(s,{gap:"200",children:[e.jsx(r,{as:"h3",variant:"headingMd",children:"Get started with products"}),e.jsxs(r,{as:"p",variant:"bodyMd",children:["Generate a product with GraphQL and get the JSON output for that product. Learn more about the"," ",e.jsx(a,{url:"https://shopify.dev/docs/api/admin-graphql/latest/mutations/productCreate",target:"_blank",removeUnderline:!0,children:"productCreate"})," ","mutation in our API references."]})]}),e.jsxs(i,{gap:"300",children:[e.jsx(m,{loading:b,onClick:c,children:"Generate a product"}),((x=t.data)==null?void 0:x.product)&&e.jsx(m,{url:`shopify:admin/products/${n}`,target:"_blank",variant:"plain",children:"View product"})]}),((g=t.data)==null?void 0:g.product)&&e.jsxs(e.Fragment,{children:[e.jsxs(r,{as:"h3",variant:"headingMd",children:[" ","productCreate mutation"]}),e.jsx(j,{padding:"400",background:"bg-surface-active",borderWidth:"025",borderRadius:"200",borderColor:"border",overflowX:"scroll",children:e.jsx("pre",{style:{margin:0},children:e.jsx("code",{children:JSON.stringify(t.data.product,null,2)})})}),e.jsxs(r,{as:"h3",variant:"headingMd",children:[" ","productVariantsBulkUpdate mutation"]}),e.jsx(j,{padding:"400",background:"bg-surface-active",borderWidth:"025",borderRadius:"200",borderColor:"border",overflowX:"scroll",children:e.jsx("pre",{style:{margin:0},children:e.jsx("code",{children:JSON.stringify(t.data.variant,null,2)})})})]})]})})}),e.jsx(o.Section,{variant:"oneThird",children:e.jsxs(s,{gap:"500",children:[e.jsx(d,{children:e.jsxs(s,{gap:"200",children:[e.jsx(r,{as:"h2",variant:"headingMd",children:"App template specs"}),e.jsxs(s,{gap:"200",children:[e.jsxs(i,{align:"space-between",children:[e.jsx(r,{as:"span",variant:"bodyMd",children:"Framework"}),e.jsx(a,{url:"https://remix.run",target:"_blank",removeUnderline:!0,children:"Remix"})]}),e.jsxs(i,{align:"space-between",children:[e.jsx(r,{as:"span",variant:"bodyMd",children:"Database"}),e.jsx(a,{url:"https://www.prisma.io/",target:"_blank",removeUnderline:!0,children:"Prisma"})]}),e.jsxs(i,{align:"space-between",children:[e.jsx(r,{as:"span",variant:"bodyMd",children:"Interface"}),e.jsxs("span",{children:[e.jsx(a,{url:"https://polaris.shopify.com",target:"_blank",removeUnderline:!0,children:"Polaris"}),", ",e.jsx(a,{url:"https://shopify.dev/docs/apps/tools/app-bridge",target:"_blank",removeUnderline:!0,children:"App Bridge"})]})]}),e.jsxs(i,{align:"space-between",children:[e.jsx(r,{as:"span",variant:"bodyMd",children:"API"}),e.jsx(a,{url:"https://shopify.dev/docs/api/admin-graphql",target:"_blank",removeUnderline:!0,children:"GraphQL API"})]})]})]})}),e.jsx(d,{children:e.jsxs(s,{gap:"200",children:[e.jsx(r,{as:"h2",variant:"headingMd",children:"Next steps"}),e.jsxs(l,{children:[e.jsxs(l.Item,{children:["Build an"," ",e.jsxs(a,{url:"https://shopify.dev/docs/apps/getting-started/build-app-example",target:"_blank",removeUnderline:!0,children:[" ","example app"]})," ","to get started"]}),e.jsxs(l.Item,{children:["Explore Shopify’s API with"," ",e.jsx(a,{url:"https://shopify.dev/docs/apps/tools/graphiql-admin-api",target:"_blank",removeUnderline:!0,children:"GraphiQL"})]})]})]})})]})})]})})]})}export{C as default};
