from . import repo


def fetch_invoice(pk):
    audit_log("fetch", pk)
    return repo.invoice_by_pk(pk)


def list_users():
    return repo.all_users()


def create_user(request):
    return repo.insert_user(request)


def audit_log(action, ref):
    return None
