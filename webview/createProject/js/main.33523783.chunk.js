(function () {
  (this["webpackJsonpcreate-project"] =
    this["webpackJsonpcreate-project"] || []).push([
    [0],
    {
      42: function (e, t, n) {},
      44: function (e, t, n) {
        "use strict";
        n.r(t);
        var a = n(1),
          c = n.n(a),
          r = n(14),
          i = n.n(r),
          o = n(5),
          s = n.n(o),
          l = n(8),
          p = n(7),
          d = n(60),
          u = n(61),
          j = n(62),
          h = n(63),
          b = n(59),
          x = Object(h.a)(function () {
            return Object(b.a)({
              wrapper: {
                width: "100%",
                height: "fit-content",
                minHeight: "100%",
                backgroundColor: "#192428",
                "& *::-webkit-scrollbar": {
                  height: "10px",
                  width: "8px",
                  backgroundColor: "#1e1e2f",
                },
                "& *::-webkit-scrollbar-thumb": {
                  borderRadius: "10px",
                  backgroundColor: "#555",
                },
                "& *::-webkit-scrollbar-track": {
                  borderRadius: "10px",
                  backgroundColor: "#1e1e2f",
                },
              },
              root: { height: "100%", padding: "32px" },
              header: { width: "100%", fontSize: "30px", color: "#f6f6f6" },
              content: {
                width: "100%",
                height: "fit-content",
                maxHeight: "100%",
              },
              title: {
                width: "100%",
                paddingTop: "24px",
                fontSize: "24px",
                color: "#eaeaea",
              },
              selectContent: {
                width: "33%",
                paddingTop: "16px",
                height: "100%",
                cursor: "pointer",
              },
              typeContent: { width: "100%", height: "fit-content" },
              typeNode: {
                width: "100%",
                height: "70px",
                display: "flex",
                minWidth: "242px",
                alignItems: "center",
                padding: "16px",
                color: "#eaeaea",
                background: "#414C50",
                "&:hover": {
                  background: "#515C60",
                  transition: "all 0.3s",
                  color: "#D5D5D5",
                },
                "&>span": { paddingLeft: "12px" },
              },
              buttonBox: {
                display: "flex",
                width: "500px",
                justifyContent: "flex-end",
              },
              button: {
                width: "100px",
                marginTop: "6px",
                marginLeft: "12px",
                height: "32px",
                color: "#f6f6f6",
                fontSize: "12px",
                borderRadius: "2px",
                border: '1px solid "#D5D5D5"',
                background: "#414C50",
                display: "flex",
                justifyContent: "center",
                alignItems: "center",
                cursor: "pointer",
                "&:hover": { background: "#515C60", transition: "all 0.3s" },
              },
              inputContent: {
                width: "500px",
                paddingTop: "16px",
                "&>input": {
                  width: "100%",
                  background: "inherit",
                  marginTop: "4px",
                  paddingLeft: "4px",
                  border: '1px solid "#D5D5D5"',
                  borderRadius: "2px",
                  color: "#f6f6f6",
                  marginBottom: "12px",
                  height: "32px",
                  lineHeight: "32px",
                },
                "&>textarea": {
                  width: "100%",
                  background: "inherit",
                  marginTop: "4px",
                  paddingLeft: "4px",
                  border: '1px solid "#D5D5D5"',
                  borderRadius: "2px",
                  color: "#f6f6f6",
                  marginBottom: "14px",
                  lineHeight: "17px",
                  fontFamily: "Arial",
                  resize: "none",
                },
                "&>span": { color: "#f6f6f6", fontSize: "12px" },
                "&>div": { color: "#f6f6f6", fontSize: "12px" },
              },
              imageUpload: {
                height: "150px",
                width: "100%",
                marginTop: "4px",
                marginBottom: "14px",
                border: '1px solid "#D5D5D5"',
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#f6f6f6",
              },
            });
          }),
          f = n(4),
          O = n(18),
          g = n.n(O),
          m = n(17),
          v = n.n(m),
          y = n(0),
          D = function (e) {
            var t = e.classes,
              n = e.setDefualtInput,
              r = e.defaultInput,
              i = e.type,
              o = c.a.useState(!1),
              d = Object(p.a)(o, 2),
              u = d[0],
              j = d[1],
              h = c.a.useState(""),
              b = Object(p.a)(h, 2),
              x = b[0],
              O = b[1],
              m = Object(a.useRef)(null),
              D = (function () {
                var e = Object(l.a)(
                  s.a.mark(function e(t) {
                    var a, c, i;
                    return s.a.wrap(function (e) {
                      for (;;)
                        switch ((e.prev = e.next)) {
                          case 0:
                            if (
                              (t.preventDefault(),
                              void 0 === (a = t.dataTransfer.files))
                            ) {
                              e.next = 10;
                              break;
                            }
                            return (
                              O(a[0].name),
                              (c = new FormData()).append("uploadFile", a[0]),
                              (e.next = 8),
                              fetch("http://localhost:8000/api/data", {
                                method: "POST",
                                body: c,
                              }).then(function (e) {
                                return e.json();
                              })
                            );
                          case 8:
                            200 === (i = e.sent).code &&
                              n(
                                Object(f.a)(
                                  Object(f.a)({}, r),
                                  {},
                                  { projectThumbnail: i.uploadFileId }
                                )
                              );
                          case 10:
                          case "end":
                            return e.stop();
                        }
                    }, e);
                  })
                );
                return function (t) {
                  return e.apply(this, arguments);
                };
              })();
            return Object(y.jsxs)("div", {
              className: t.content,
              children: [
                Object(y.jsx)("div", {
                  className: t.title,
                  children: "Write Information of project",
                }),
                Object(y.jsxs)("div", {
                  className: t.inputContent,
                  children: [
                    Object(y.jsx)("span", { children: "Project ID" }),
                    Object(y.jsx)("input", {
                      placeholder: "Input Project Name",
                      onChange: function (e) {
                        n(
                          Object(f.a)(
                            Object(f.a)({}, r),
                            {},
                            { projectName: e.target.value }
                          )
                        );
                      },
                      value: r.projectName,
                    }),
                    Object(y.jsx)("span", { children: "Project Description" }),
                    Object(y.jsx)("textarea", {
                      rows: 10,
                      placeholder: "Input Project Description",
                      onChange: function (e) {
                        n(
                          Object(f.a)(
                            Object(f.a)({}, r),
                            {},
                            { projectDescription: e.target.value }
                          )
                        );
                      },
                      value: r.projectDescription,
                    }),
                    Object(y.jsx)("span", { children: "Project Thumbnail" }),
                    Object(y.jsx)("div", {
                      className: t.imageUpload,
                      onDragOver: function (e) {
                        e.preventDefault();
                      },
                      onDragEnter: function (e) {
                        e.preventDefault(), j(!0);
                      },
                      onDragLeave: function (e) {
                        e.preventDefault(), j(!1);
                      },
                      onDrop: D,
                      onClick: function () {
                        return m.current.click();
                      },
                      children: u
                        ? Object(y.jsxs)("div", {
                            style: {
                              textAlign: "center",
                              pointerEvents: "none",
                            },
                            children: [
                              Object(y.jsx)(v.a, {
                                style: { width: "40px", height: "40px" },
                              }),
                              Object(y.jsx)("br", {}),
                              Object(y.jsx)("span", {
                                children: "" !== x ? x : "Drop Image",
                              }),
                            ],
                          })
                        : Object(y.jsx)(y.Fragment, {
                            children: Object(y.jsxs)("div", {
                              style: { textAlign: "center" },
                              children: [
                                Object(y.jsx)(g.a, {
                                  style: { width: "40px", height: "40px" },
                                }),
                                Object(y.jsx)("br", {}),
                                Object(y.jsx)("span", {
                                  children:
                                    "edit" === i
                                      ? "If you want change iamge, upload image"
                                      : "Drag and Drop Image or Click to upload Image",
                                }),
                              ],
                            }),
                          }),
                    }),
                    Object(y.jsx)("input", {
                      type: "file",
                      id: "getFile",
                      style: { display: "none" },
                      ref: m,
                      onChange: (function () {
                        var e = Object(l.a)(
                          s.a.mark(function e(t) {
                            var a, c, i;
                            return s.a.wrap(function (e) {
                              for (;;)
                                switch ((e.prev = e.next)) {
                                  case 0:
                                    if (null === (a = t.target.files)) {
                                      e.next = 8;
                                      break;
                                    }
                                    return (
                                      (c = new FormData()).append(
                                        "uploadFile",
                                        a[0]
                                      ),
                                      (e.next = 6),
                                      fetch("http://localhost:8000/api/data", {
                                        method: "POST",
                                        body: c,
                                      }).then(function (e) {
                                        return e.json();
                                      })
                                    );
                                  case 6:
                                    200 === (i = e.sent).code &&
                                      (j(!0),
                                      O(a[0].name),
                                      n(
                                        Object(f.a)(
                                          Object(f.a)({}, r),
                                          {},
                                          { projectThumbnail: i.uploadFileId }
                                        )
                                      ));
                                  case 8:
                                  case "end":
                                    return e.stop();
                                }
                            }, e);
                          })
                        );
                        return function (t) {
                          return e.apply(this, arguments);
                        };
                      })(),
                    }),
                    Object(y.jsx)("span", { children: "Project Participant" }),
                    Object(y.jsx)("input", {
                      placeholder:
                        "Input project Participane ex)test1,test2,test3... ",
                      value: r.projectParticipants,
                      onChange: function (e) {
                        n(
                          Object(f.a)(
                            Object(f.a)({}, r),
                            {},
                            { projectParticipants: e.target.value }
                          )
                        );
                      },
                    }),
                  ],
                }),
              ],
            });
          },
          w = n(26),
          C = function (e) {
            var t = e.type,
              n = e.classes,
              r = e.setSource,
              i = e.source,
              o = c.a.useState(!1),
              d = Object(p.a)(o, 2),
              u = d[0],
              j = d[1],
              h = c.a.useState(""),
              b = Object(p.a)(h, 2),
              x = b[0],
              O = b[1],
              m = Object(a.useRef)(null),
              D = (function () {
                var e = Object(l.a)(
                  s.a.mark(function e(t) {
                    var n, a, c, o;
                    return s.a.wrap(function (e) {
                      for (;;)
                        switch ((e.prev = e.next)) {
                          case 0:
                            if (
                              (t.preventDefault(),
                              void 0 === (n = t.dataTransfer.files))
                            ) {
                              e.next = 10;
                              break;
                            }
                            return (
                              O(n[0].name),
                              (a = new FormData()).append("uploadFile", n[0]),
                              (e.next = 8),
                              fetch("http://localhost:8000/api/data", {
                                method: "POST",
                                body: a,
                              }).then(function (e) {
                                return e.json();
                              })
                            );
                          case 8:
                            200 === (c = e.sent).code &&
                              (((o = i).upload.uploadFileId = c.uploadFileId),
                              r(o));
                          case 10:
                          case "end":
                            return e.stop();
                        }
                    }, e);
                  })
                );
                return function (t) {
                  return e.apply(this, arguments);
                };
              })();
            return "git" === t
              ? Object(y.jsxs)(y.Fragment, {
                  children: [
                    Object(y.jsx)("div", {
                      className: n.title,
                      children: "Input Optional info about git",
                    }),
                    Object(y.jsxs)("div", {
                      className: n.inputContent,
                      children: [
                        Object(y.jsx)("span", { children: "Project ID" }),
                        Object(y.jsx)("input", {
                          placeholder: "Input Github Url",
                          onChange: function (e) {
                            r(
                              Object(f.a)(
                                Object(f.a)({}, i),
                                {},
                                { gitUrl: e.target.value }
                              )
                            );
                          },
                          value: void 0 === i ? "" : i.gitUrl,
                        }),
                      ],
                    }),
                  ],
                })
              : "upload" === t
              ? Object(y.jsxs)(y.Fragment, {
                  children: [
                    Object(y.jsx)("div", {
                      className: n.title,
                      children: "Input Optional info about Upload",
                    }),
                    Object(y.jsxs)("div", {
                      className: n.inputContent,
                      children: [
                        Object(y.jsx)("span", { children: "Project Zip File" }),
                        Object(y.jsx)("div", {
                          className: n.imageUpload,
                          onDragOver: function (e) {
                            e.preventDefault();
                          },
                          onDragEnter: function (e) {
                            e.preventDefault(), j(!0);
                          },
                          onDragLeave: function (e) {
                            e.preventDefault(), j(!1);
                          },
                          onDrop: D,
                          onClick: function () {
                            return m.current.click();
                          },
                          children: u
                            ? Object(y.jsxs)("div", {
                                style: {
                                  textAlign: "center",
                                  pointerEvents: "none",
                                },
                                children: [
                                  Object(y.jsx)(v.a, {
                                    style: { width: "40px", height: "40px" },
                                  }),
                                  Object(y.jsx)("br", {}),
                                  Object(y.jsx)("span", {
                                    children: "" !== x ? x : "Drop File",
                                  }),
                                ],
                              })
                            : Object(y.jsx)(y.Fragment, {
                                children: Object(y.jsxs)("div", {
                                  style: { textAlign: "center" },
                                  children: [
                                    Object(y.jsx)(g.a, {
                                      style: { width: "40px", height: "40px" },
                                    }),
                                    Object(y.jsx)("br", {}),
                                    Object(y.jsx)("span", {
                                      children:
                                        "Drag and Drop File or Click to upload File",
                                    }),
                                  ],
                                }),
                              }),
                        }),
                        Object(y.jsx)("input", {
                          ref: m,
                          style: { display: "none" },
                          type: "file",
                          id: "getFile",
                          onChange: (function () {
                            var e = Object(l.a)(
                              s.a.mark(function e(t) {
                                var n, a, c, o;
                                return s.a.wrap(function (e) {
                                  for (;;)
                                    switch ((e.prev = e.next)) {
                                      case 0:
                                        if (null === (n = t.target.files)) {
                                          e.next = 8;
                                          break;
                                        }
                                        return (
                                          (a = new FormData()).append(
                                            "uploadFile",
                                            n[0]
                                          ),
                                          (e.next = 6),
                                          fetch(
                                            "http://localhost:8000/api/data",
                                            { method: "POST", body: a }
                                          ).then(function (e) {
                                            return e.json();
                                          })
                                        );
                                      case 6:
                                        200 === (c = e.sent).code &&
                                          (((o = i).upload.uploadFileId =
                                            c.uploadFileId),
                                          r(o));
                                      case 8:
                                      case "end":
                                        return e.stop();
                                    }
                                }, e);
                              })
                            );
                            return function (t) {
                              return e.apply(this, arguments);
                            };
                          })(),
                        }),
                        Object(y.jsxs)("div", {
                          style: { display: "inline-block" },
                          children: [
                            "is Extract?",
                            Object(y.jsx)("input", {
                              type: "checkbox",
                              checked: !i.upload || i.upload.isExtract,
                              onClick: function (e) {
                                var t = Object(w.cloneDeep)(i);
                                (t.upload.isExtract = e.currentTarget.checked),
                                  r(t);
                              },
                              style: { verticalAlign: "middle" },
                            }),
                          ],
                        }),
                      ],
                    }),
                  ],
                })
              : Object(y.jsx)(y.Fragment, {});
          };
        n(42);
        var k = function () {
            var e = x(),
              t = Object(a.useState)(""),
              n = Object(p.a)(t, 2),
              c = n[0],
              r = n[1],
              i = Object(a.useState)({
                projectDescription: "",
                projectName: "",
                projectParticipants: void 0,
                projectThumbnail: void 0,
              }),
              o = Object(p.a)(i, 2),
              h = o[0],
              b = o[1],
              f = Object(a.useState)(),
              O = Object(p.a)(f, 2),
              g = O[0],
              m = O[1];
            Object(a.useEffect)(
              function () {
                m(
                  "git" === c
                    ? { type: "gitUrl", gitUrl: void 0 }
                    : "upload" === c
                    ? {
                        type: "upload",
                        upload: { uploadFileId: void 0, isExtract: !0 },
                      }
                    : { type: "nothing" }
                );
              },
              [c]
            );
            var v = (function () {
              var e = Object(l.a)(
                s.a.mark(function e() {
                  var t, n;
                  return s.a.wrap(function (e) {
                    for (;;)
                      switch ((e.prev = e.next)) {
                        case 0:
                          return (
                            (t = h),
                            void 0 !== h.projectParticipants &&
                              (t.projectParticipants =
                                h.projectParticipants.split(",")),
                            (n = { projectInfo: t, source: g }),
                            (e.next = 5),
                            fetch("http://localhost:8000/api/project", {
                              method: "POST",
                              mode: "cors",
                              headers: { "Content-Type": "application/json" },
                              body: JSON.stringify(n),
                            }).then(function (e) {
                              return e.json();
                            })
                          );
                        case 5:
                          200 === e.sent.code && (window.location.href = "/");
                        case 7:
                        case "end":
                          return e.stop();
                      }
                  }, e);
                })
              );
              return function () {
                return e.apply(this, arguments);
              };
            })();
            return Object(y.jsx)("div", {
              className: e.wrapper,
              children: Object(y.jsxs)("div", {
                className: e.root,
                children: [
                  Object(y.jsx)("div", {
                    className: e.header,
                    children: "Create Project",
                  }),
                  "" === c &&
                    Object(y.jsxs)("div", {
                      className: e.content,
                      children: [
                        Object(y.jsx)("div", {
                          className: e.title,
                          children: "Select Project Type",
                        }),
                        Object(y.jsxs)("div", {
                          className: e.typeContent,
                          children: [
                            Object(y.jsx)("div", {
                              className: e.selectContent,
                              onClick: function () {
                                return r("defualt");
                              },
                              children: Object(y.jsxs)("div", {
                                className: e.typeNode,
                                children: [
                                  Object(y.jsx)(d.a, {}),
                                  Object(y.jsx)("span", {
                                    children: "Create a Project",
                                  }),
                                ],
                              }),
                            }),
                            Object(y.jsx)("div", {
                              className: e.selectContent,
                              onClick: function () {
                                return r("git");
                              },
                              children: Object(y.jsxs)("div", {
                                className: e.typeNode,
                                children: [
                                  Object(y.jsx)(u.a, {}),
                                  Object(y.jsx)("span", {
                                    children: "Clone project in Git",
                                  }),
                                ],
                              }),
                            }),
                            Object(y.jsx)("div", {
                              className: e.selectContent,
                              onClick: function () {
                                return r("upload");
                              },
                              children: Object(y.jsxs)("div", {
                                className: e.typeNode,
                                children: [
                                  Object(y.jsx)(j.a, {}),
                                  Object(y.jsx)("span", {
                                    children: "Upload your own Project",
                                  }),
                                ],
                              }),
                            }),
                          ],
                        }),
                      ],
                    }),
                  "" !== c &&
                    Object(y.jsx)(D, {
                      classes: e,
                      setDefualtInput: b,
                      defaultInput: h,
                    }),
                  "" !== c &&
                    Object(y.jsx)(C, {
                      type: c,
                      classes: e,
                      setSource: m,
                      source: g,
                    }),
                  "" !== c &&
                    Object(y.jsxs)("div", {
                      className: e.buttonBox,
                      children: [
                        Object(y.jsx)("div", {
                          className: e.button,
                          onClick: function () {
                            return r("");
                          },
                          children: "PREV",
                        }),
                        Object(y.jsx)("div", {
                          className: e.button,
                          onClick: function () {
                            return v();
                          },
                          children: "SUBMIT",
                        }),
                      ],
                    }),
                ],
              }),
            });
          },
          N = function (e) {
            e &&
              e instanceof Function &&
              n
                .e(3)
                .then(n.bind(null, 65))
                .then(function (t) {
                  var n = t.getCLS,
                    a = t.getFID,
                    c = t.getFCP,
                    r = t.getLCP,
                    i = t.getTTFB;
                  n(e), a(e), c(e), r(e), i(e);
                });
          };
        i.a.render(
          Object(y.jsx)(c.a.StrictMode, { children: Object(y.jsx)(k, {}) }),
          document.getElementById("root")
        ),
          N();
      },
    },
    [[44, 1, 2]],
  ]);
  //# sourceMappingURL=main.33523783.chunk.js.map
})();
