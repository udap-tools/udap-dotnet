using Microsoft.AspNetCore.Mvc;
using Udap.Common.Models;
using Udap.Idp.Admin.Services.DataBase;
using Udap.Server.Mappers;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Udap.Idp.Admin.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CommunityController : ControllerBase
    {
        ICommunityService _dbService;

        public CommunityController(ICommunityService dbService) {
            _dbService = dbService;
        }

        // GET: api/<CommnityController>
        [HttpGet]
        public async Task<ActionResult<IEnumerable<Community>>> GetAsync(CancellationToken token)
        {
            var entitities = await _dbService.Get(token);
            
            if (!entitities.Any())
            {
                return NotFound();
            }
            
            var communities = entitities.Select(e => e.ToModel());

            return Ok(communities);
        }

        // GET api/<CommnityController>/5
        [HttpGet("{id}")]
        public async Task<ActionResult<Community>> Get(int id, CancellationToken token)
        {
            var entity = await _dbService.Get(id, token);

            if (entity == null)
            {
                return NotFound();
            }
            var community = entity.ToModel();

            return Ok(community);
        }

        // POST api/<CommnityController>
        [HttpPost]
        public void Post([FromBody] Anchor value, CancellationToken token)
        {

        }

        // PUT api/<CommnityController>/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] Anchor value, CancellationToken token)
        {
        }

        // DELETE api/<CommnityController>/5
        [HttpDelete("{id}")]
        public void Delete(int id, CancellationToken token)
        {
        }
    }
}