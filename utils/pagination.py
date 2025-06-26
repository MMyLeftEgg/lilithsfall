from flask import request, url_for
from math import ceil

class Pagination:
    """Classe para gerenciar paginação"""
    
    def __init__(self, page, per_page, total_count, items):
        self.page = page
        self.per_page = per_page
        self.total_count = total_count
        self.items = items
        
    @property
    def pages(self):
        """Número total de páginas"""
        return ceil(self.total_count / self.per_page)
    
    @property
    def has_prev(self):
        """Verifica se há página anterior"""
        return self.page > 1
    
    @property
    def prev_num(self):
        """Número da página anterior"""
        return self.page - 1 if self.has_prev else None
    
    @property
    def has_next(self):
        """Verifica se há próxima página"""
        return self.page < self.pages
    
    @property
    def next_num(self):
        """Número da próxima página"""
        return self.page + 1 if self.has_next else None
    
    def iter_pages(self, left_edge=2, left_current=2, right_current=3, right_edge=2):
        """Itera sobre números de páginas para exibição"""
        last = self.pages
        for num in range(1, last + 1):
            if num <= left_edge or \
               (self.page - left_current - 1 < num < self.page + right_current) or \
               num > last - right_edge:
                yield num

def paginate_query(query, page=None, per_page=20, error_out=True):
    """Pagina uma query SQLAlchemy"""
    if page is None:
        page = request.args.get('page', 1, type=int)
    
    if page < 1:
        if error_out:
            raise ValueError('Página deve ser >= 1')
        page = 1
    
    # Calcular offset
    offset = (page - 1) * per_page
    
    # Obter total de itens
    total = query.count()
    
    # Obter itens da página atual
    items = query.offset(offset).limit(per_page).all()
    
    return Pagination(page, per_page, total, items)

def get_pagination_info(page, per_page, total_count):
    """Retorna informações de paginação para templates"""
    total_pages = ceil(total_count / per_page)
    
    return {
        'page': page,
        'per_page': per_page,
        'total_count': total_count,
        'total_pages': total_pages,
        'has_prev': page > 1,
        'has_next': page < total_pages,
        'prev_num': page - 1 if page > 1 else None,
        'next_num': page + 1 if page < total_pages else None,
        'start_index': (page - 1) * per_page + 1,
        'end_index': min(page * per_page, total_count)
    }

def generate_pagination_urls(endpoint, page, total_pages, **kwargs):
    """Gera URLs para navegação de páginas"""
    urls = {}
    
    if page > 1:
        urls['prev'] = url_for(endpoint, page=page-1, **kwargs)
        urls['first'] = url_for(endpoint, page=1, **kwargs)
    
    if page < total_pages:
        urls['next'] = url_for(endpoint, page=page+1, **kwargs)
        urls['last'] = url_for(endpoint, page=total_pages, **kwargs)
    
    # URLs para páginas específicas
    urls['pages'] = {}
    for p in range(max(1, page-2), min(total_pages+1, page+3)):
        urls['pages'][p] = url_for(endpoint, page=p, **kwargs)
    
    return urls

def create_search_pagination(query, search_term, page=1, per_page=10):
    """Cria paginação para resultados de busca"""
    if search_term:
        # Aplicar filtro de busca
        filtered_query = query.filter(
            query.model.title.contains(search_term) |
            query.model.description.contains(search_term)
        )
    else:
        filtered_query = query
    
    return paginate_query(filtered_query, page, per_page)

class PaginationHelper:
    """Helper para facilitar uso de paginação em templates"""
    
    @staticmethod
    def get_page_range(current_page, total_pages, max_pages=10):
        """Retorna range de páginas para exibir"""
        if total_pages <= max_pages:
            return list(range(1, total_pages + 1))
        
        # Calcular início e fim do range
        half_max = max_pages // 2
        start = max(1, current_page - half_max)
        end = min(total_pages, start + max_pages - 1)
        
        # Ajustar se necessário
        if end - start + 1 < max_pages:
            start = max(1, end - max_pages + 1)
        
        return list(range(start, end + 1))
    
    @staticmethod
    def get_pagination_summary(page, per_page, total_count):
        """Retorna resumo da paginação (ex: 'Mostrando 1-10 de 50 resultados')"""
        if total_count == 0:
            return "Nenhum resultado encontrado"
        
        start = (page - 1) * per_page + 1
        end = min(page * per_page, total_count)
        
        if total_count == 1:
            return "1 resultado"
        elif start == end:
            return f"Resultado {start} de {total_count}"
        else:
            return f"Mostrando {start}-{end} de {total_count} resultados"