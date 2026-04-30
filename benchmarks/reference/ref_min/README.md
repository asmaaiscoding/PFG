# Reference Django app: ref_min

A minimal Django source tree used as a fixture for the endpoint-discovery
extractor. We never run Django; we only parse the source files. Therefore no
`manage.py`, `settings.py`, or migrations are required.

Structure:

```
ref_min/
  blog/
    urls.py        — path() + re_path() + include() patterns
    views.py       — FBVs + CBVs + DRF views
  api/
    urls.py        — DRF router
    views.py       — ViewSet, APIView
  urls.py          — root URL conf, includes blog and api
```

Expected endpoints (ground truth lives in `expected_endpoints.yaml`):

| Method | Route                              | Handler                       |
|--------|------------------------------------|-------------------------------|
| GET    | /blog/                             | blog.views.index              |
| GET    | /blog/post/<int:pk>/               | blog.views.PostDetail.get     |
| POST   | /blog/post/                        | blog.views.PostCreate.post    |
| GET    | /api/users/                        | api.views.UserViewSet.list    |
| POST   | /api/users/                        | api.views.UserViewSet.create  |
| GET    | /api/users/<pk>/                   | api.views.UserViewSet.retrieve|
| PUT    | /api/users/<pk>/                   | api.views.UserViewSet.update  |
| DELETE | /api/users/<pk>/                   | api.views.UserViewSet.destroy |
| GET    | /api/health/                       | api.views.HealthAPIView.get   |
